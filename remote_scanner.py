import paramiko
import configparser
import re
import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime

# --- 로거 설정 ---
def setup_logger():
    log_dir = "conf"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log_filename = os.path.join(log_dir, f"scan_log_{datetime.now().strftime('%Y-%m-%d')}.log")

    logger = logging.getLogger("RemoteScanner")
    logger.setLevel(logging.INFO)

    # 핸들러가 이미 추가되었는지 확인하여 중복 로깅 방지
    if not logger.handlers:
        # 20MB 크기 제한으로 로그 파일 분리
        handler = RotatingFileHandler(log_filename, maxBytes=20*1024*1024, backupCount=5, encoding='utf-8')
        formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger

class RemoteScanner:
    def __init__(self, result_queue, status_callback):
        """
        :param result_queue: 스캔 결과를 GUI로 전달하기 위한 Queue
        :param status_callback: 현재 상태를 GUI로 전달하기 위한 콜백 함수
        """
        self.result_queue = result_queue
        self.status_callback = status_callback
        self.patterns = self._load_patterns()
        self.logger = setup_logger()
        self.ssh = None
        self.sftp = None

    def _load_patterns(self):
        """conf/pattern.ini 파일에서 정규식 패턴을 로드합니다."""
        patterns = []
        # RawConfigParser를 사용하여 정규식의 '%'와 같은 특수 문자가 보간(interpolation) 기능으로
        # 해석되어 발생하는 오류를 방지합니다.
        parser = configparser.RawConfigParser()
        try:
            parser.read('conf/pattern.ini', encoding='utf-8')
            for section in parser.sections():
                if 'regex' in parser[section] and 'alias' in parser[section]:
                    patterns.append({
                        'regex': re.compile(parser[section]['regex']),
                        'alias': parser[section]['alias']
                    })
            self.status_callback(f"패턴 {len(patterns)}개 로드 완료.")
        except Exception as e:
            self.status_callback(f"패턴 파일 읽기 오류: {e}")
            # GUI에 오류를 표시하기 위해 큐에 넣을 수도 있습니다.
            self.result_queue.put(f"오류: conf/pattern.ini 파일을 읽을 수 없습니다. {e}")
        return patterns

    def connect(self, host, port, username, password):
        """Paramiko를 사용하여 원격 서버에 접속합니다."""
        try:
            self.status_callback(f"{host}에 접속 시도 중...")
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(host, port=int(port), username=username, password=password, timeout=10)
            self.sftp = self.ssh.open_sftp()
            self.status_callback(f"{host}에 성공적으로 접속했습니다.")
            return True
        except Exception as e:
            error_msg = f"접속 실패: {e}"
            self.status_callback(error_msg)
            self.result_queue.put(f"오류: {error_msg}")
            return False

    def disconnect(self):
        """원격 서버 접속을 종료합니다."""
        if self.sftp:
            self.sftp.close()
        if self.ssh:
            self.ssh.close()
        self.status_callback("접속이 종료되었습니다.")

    def find_files(self, start_path, extensions):
        """원격지에서 지정된 확장자의 파일 목록을 재귀적으로 찾습니다."""
        self.status_callback(f"{start_path}에서 파일 검색 중...")

        # 확장자 문자열을 리스트로 변환 (예: "*.log,*.txt" -> ["*.log", "*.txt"])
        ext_list = [ext.strip() for ext in extensions.split(',')]

        # find 명령어 생성
        # 예: find /home -type f \( -name "*.log" -o -name "*.txt" \)
        find_command = f"find {start_path} -type f"
        if ext_list:
            name_conditions = " -o ".join([f"-name '{ext}'" for ext in ext_list])
            find_command += f" \\( {name_conditions} \\)"

        stdin, stdout, stderr = self.ssh.exec_command(find_command)

        error = stderr.read().decode().strip()
        if error:
            self.status_callback(f"파일 검색 오류: {error}")
            self.result_queue.put(f"오류: {error}")
            return

        file_list = stdout.read().decode().splitlines()
        self.status_callback(f"총 {len(file_list)}개의 파일을 찾았습니다. 스캔을 시작합니다.")
        yield from file_list


    def scan_file(self, filepath):
        """
        단일 원격 파일을 스캔하여 민감 정보를 찾습니다.
        모든 패턴을 하나로 묶어 grep을 한 번만 실행하고, 결과를 가져와 Python에서 분석합니다.
        이 방식은 SSH 연결 오버헤드를 줄이고, 쉘 이스케이핑 문제를 회피하여 정확성과 성능을 높입니다.
        """
        try:
            if not self.patterns:
                return  # 스캔할 패턴이 없으면 종료

            # 1. 모든 패턴을 '|'로 묶어 하나의 거대 패턴 생성
            # 각 패턴을 괄호로 감싸서 개별 패턴의 무결성 보장
            combined_regex = "|".join(f"({p['regex'].pattern})" for p in self.patterns)

            # 2. 파일당 한 번만 grep 실행하여 일치하는 모든 문자열을 가져옴
            command = f"grep -oP '{combined_regex}' \"{filepath}\""

            stdin, stdout, stderr = self.ssh.exec_command(command, timeout=30)
            matched_lines = stdout.read().decode('utf-8', errors='ignore').splitlines()
            err_str = stderr.read().decode('utf-8', errors='ignore').strip()

            # 오류 처리
            if err_str:
                if "No such file or directory" in err_str or "Permission denied" in err_str:
                    self.logger.error(f"파일 접근 불가, 스캔 중단 [{filepath}]: {err_str}")
                    return # 이 파일 스캔 중단
                # 바이너리 파일 경고는 무시
                elif "binary file matches" not in err_str.lower():
                    self.logger.warning(f"Grep 실행 중 경고 [{filepath}]: {err_str}")

            if not matched_lines:
                return  # 일치하는 내용이 없으면 종료

            # 3. Python에서 결과 분석 및 카운팅
            found_by_alias = {p['alias']: 0 for p in self.patterns}
            for line in matched_lines:
                for p in self.patterns:
                    # fullmatch를 사용하여 grep -o로 나온 결과 전체가 패턴과 일치하는지 확인
                    if p['regex'].fullmatch(line.strip()):
                        found_by_alias[p['alias']] += 1
                        break  # 다음 라인으로

            # 검출된 항목만 필터링
            final_counts = {alias: count for alias, count in found_by_alias.items() if count > 0}

            if not final_counts:
                return

            # 4. 결과 보고
            total_found_count = sum(final_counts.values())
            details_str = ", ".join([f"{alias}: {count}" for alias, count in final_counts.items()])
            result_msg = f"검출 완료 [{filepath}] 총 {total_found_count}개 ({details_str})"

            self.logger.info(result_msg)
            self.result_queue.put({"filepath": filepath, "details": f"총 {total_found_count}개 ({details_str})"})

        except Exception as e:
            self.logger.error(f"예상치 못한 스캔 오류 발생 [{filepath}]: {e}")


    def start_scan(self, host, port, username, password, start_path, extensions):
        """스캔 프로세스를 시작합니다."""
        if not self.connect(host, port, username, password):
            self.result_queue.put("FINISH")
            return

        try:
            files_to_scan = self.find_files(start_path, extensions)
            for filepath in files_to_scan:
                self.status_callback(f"스캔 중: {filepath}")
                self.scan_file(filepath)

            self.status_callback("모든 파일 스캔 완료.")

        except Exception as e:
            error_msg = f"스캔 중 심각한 오류 발생: {e}"
            self.status_callback(error_msg)
            self.result_queue.put(f"오류: {error_msg}")

        finally:
            self.disconnect()
            # 작업 완료를 GUI에 알림
            self.result_queue.put("FINISH")