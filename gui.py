import tkinter as tk
from tkinter import ttk, messagebox
import threading
import queue
from remote_scanner import RemoteScanner

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("민감 정보 원격 스캐너")
        self.geometry("800x600")

        self.result_queue = queue.Queue()

        # 프레임 생성
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- 접속 정보 프레임 ---
        conn_frame = ttk.LabelFrame(main_frame, text="원격 접속 정보", padding="10")
        conn_frame.pack(fill=tk.X, pady=5)
        conn_frame.columnconfigure(1, weight=1)
        conn_frame.columnconfigure(3, weight=1)

        # 호스트
        ttk.Label(conn_frame, text="호스트:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.host_entry = ttk.Entry(conn_frame)
        self.host_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)

        # 포트
        ttk.Label(conn_frame, text="포트:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.port_entry = ttk.Entry(conn_frame, width=10)
        self.port_entry.insert(0, "22")
        self.port_entry.grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)

        # 사용자명
        ttk.Label(conn_frame, text="사용자명:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.user_entry = ttk.Entry(conn_frame)
        self.user_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)

        # 비밀번호
        ttk.Label(conn_frame, text="비밀번호:").grid(row=1, column=2, padx=5, pady=5, sticky=tk.W)
        self.pass_entry = ttk.Entry(conn_frame, show="*")
        self.pass_entry.grid(row=1, column=3, padx=5, pady=5, sticky=tk.EW)

        # --- 스캔 설정 프레임 ---
        scan_frame = ttk.LabelFrame(main_frame, text="스캔 설정", padding="10")
        scan_frame.pack(fill=tk.X, pady=5)
        scan_frame.columnconfigure(1, weight=1)

        # 스캔 디렉토리
        ttk.Label(scan_frame, text="시작 디렉토리:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.dir_entry = ttk.Entry(scan_frame)
        self.dir_entry.insert(0, "/home")
        self.dir_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)

        # 파일 확장자
        ttk.Label(scan_frame, text="파일 확장자:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.ext_entry = ttk.Entry(scan_frame)
        self.ext_entry.insert(0, "*.log,*.txt,*.md")
        self.ext_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)

        # --- 버튼 프레임 ---
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=5)

        self.scan_button = ttk.Button(button_frame, text="🔍 검출 시작", command=self.start_scan_thread)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = ttk.Button(button_frame, text="🗑️ 목록 지우기", command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        self.status_label = ttk.Label(button_frame, text="대기중...")
        self.status_label.pack(side=tk.RIGHT, padx=5)

        # --- 결과 리스트 프레임 ---
        result_frame = ttk.LabelFrame(main_frame, text="검출 결과", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.result_tree = ttk.Treeview(
            result_frame,
            columns=("filepath", "details"),
            show="headings"
        )
        self.result_tree.heading("filepath", text="파일 경로")
        self.result_tree.heading("details", text="검출 내역")
        self.result_tree.column("filepath", width=400)

        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.result_tree.yview)
        self.result_tree.configure(yscroll=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_tree.pack(fill=tk.BOTH, expand=True)

        self.process_queue()

    def start_scan_thread(self):
        """스캐너를 별도의 스레드에서 실행합니다."""
        host = self.host_entry.get()
        port = self.port_entry.get()
        user = self.user_entry.get()
        password = self.pass_entry.get()
        start_dir = self.dir_entry.get()
        extensions = self.ext_entry.get()

        if not all([host, port, user, start_dir, extensions]):
            messagebox.showerror("입력 오류", "비밀번호를 제외한 모든 필드를 입력해야 합니다.")
            return

        self.scan_button.config(state=tk.DISABLED)
        self.clear_results()

        scanner = RemoteScanner(self.result_queue, self.update_status)

        scan_thread = threading.Thread(
            target=scanner.start_scan,
            args=(host, port, user, password, start_dir, extensions),
            daemon=True
        )
        scan_thread.start()

    def process_queue(self):
        """주기적으로 큐를 확인하여 GUI를 업데이트합니다."""
        try:
            while True:
                msg = self.result_queue.get_nowait()
                if isinstance(msg, dict):
                    self.result_tree.insert("", tk.END, values=(msg["filepath"], msg["details"]))
                elif isinstance(msg, str) and msg.startswith("오류:"):
                    messagebox.showerror("오류", msg)
                elif msg == "FINISH":
                    self.scan_button.config(state=tk.NORMAL)
                    self.update_status("스캔 완료. 대기중...")
                    messagebox.showinfo("완료", "모든 스캔 작업이 완료되었습니다.")
                    break # 추가적인 FINISH 메시지 처리를 막기 위해 루프 종료
        except queue.Empty:
            pass
        finally:
            self.after(100, self.process_queue)

    def update_status(self, text):
        """상태 표시줄 레이블을 업데이트합니다."""
        self.status_label.config(text=text)

    def clear_results(self):
        """결과 목록을 모두 지웁니다."""
        for i in self.result_tree.get_children():
            self.result_tree.delete(i)
        self.update_status("대기중...")