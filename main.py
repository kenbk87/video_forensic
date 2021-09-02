from PyQt5.QtWidgets import *
from PyQt5 import uic
import moviepy.editor
import sys
import os
import hashlib
import pymediainfo
import json


# Load giao diện chính:
class UI(QMainWindow):
    def __init__(self):
        super(UI, self).__init__()
        uic.loadUi('video forensic.ui', self)

        # Liên kết với giao diện:
        # Phần chung:
        self.edt_duong_dan = self.findChild(QTextEdit, 'edt_duong_dan')
        self.btn_chon_tep_tin = self.findChild(QPushButton, 'btn_chon_tep_tin')
        self.btn_chon_thu_muc = self.findChild(QPushButton, 'btn_chon_thu_muc')
        self.edt_log = self.findChild(QTextEdit, 'edt_log')
        self.btn_xoa_log = self.findChild(QPushButton, 'btn_xoa_log')
        self.pb_progress_bar = self.findChild(QProgressBar, 'progress_bar')
        self.pb_progress_bar.setValue(0)

        # Tab Mã hash:
        self.rd_md5 = self.findChild(QRadioButton, 'rd_md5')
        self.rd_sha1 = self.findChild(QRadioButton, 'rd_sha1')
        self.rd_sha256 = self.findChild(QRadioButton, 'rd_sha256')
        self.rd_md5.setChecked(True)  # Đặt chế độ mặc định lấy mã hash theo mã MD5.
        self.btn_hash = self.findChild(QPushButton, 'btn_hash')
        self.btn_sao_chep = self.findChild(QPushButton, 'btn_sao_chep')
        self.edt_ket_qua_hash = self.findChild(QTextEdit, 'edt_ket_qua_hash')

        # Tab Thuộc tính tệp tin:
        self.btn_xem_thuoc_tinh = self.findChild(QPushButton, 'btn_xem_thuoc_tinh')
        self.edt_ket_qua_thuoc_tinh = self.findChild(QTextEdit, 'edt_ket_qua_thuoc_tinh')
        self.btn_sao_chep_thuoc_tinh = self.findChild(QPushButton, 'btn_sao_chep_thuoc_tinh')
        self.btn_xoa = self.findChild(QPushButton, 'btn_xoa')
        self.btn_trich_frame = self.findChild(QPushButton, 'btn_trich_frame')
        self.tb_hyperlink = self.findChild(QTextBrowser, 'tb_hyperlink')

        # Tab convert:
        self.btn_chon_thu_muc_luu_audio = self.findChild(QPushButton, 'btn_chon_thu_muc_luu_audio')
        self.btn_chon_thu_muc_luu_video = self.findChild(QPushButton, 'btn_chon_thu_muc_luu_video')
        self.cb_audio = self.findChild(QComboBox, 'cb_audio')
        self.cb_video = self.findChild(QComboBox, 'cb_video')
        self.btn_convert_audio = self.findChild(QPushButton, 'btn_convert_audio')
        self.btn_convert_video = self.findChild(QPushButton, 'btn_convert_video')
################################################################################################################
        # Liên kết các sự kiện người dùng đến các hàm chức năng:
        # Phần chung:
        self.btn_chon_tep_tin.clicked.connect(self.clicked_chon_tep_tin)
        self.btn_chon_thu_muc.clicked.connect(self.clicked_chon_thu_muc)
        self.btn_xoa_log.clicked.connect(self.xoa_log)

        # Tab Mã hash:
        self.btn_hash.clicked.connect(self.hash)
        self.btn_sao_chep.clicked.connect(self.clicked_sao_chep)

        # Tab Thuộc tính tệp tin:
        self.btn_xem_thuoc_tinh.clicked.connect(self.xem_thong_tin)
        self.btn_trich_frame.clicked.connect(self.trich_frame)
        self.btn_sao_chep_thuoc_tinh.clicked.connect(self.sao_chep_thuoc_tinh)
        self.btn_xoa.clicked.connect(self.xoa)

        # Tab convert:
        self.btn_convert_audio.clicked.connect(self.convert_audio_click)

        self.show()
#################################################################################################################

    # Hàm chức năng khi sự kiện khi ấn nút chọn thư mục được thực hiện:
    def clicked_chon_thu_muc(self):
        # Chọn thư mục cần lấy mã:
        ten_folder = QFileDialog.getExistingDirectory(self, 'Chọn thư mục chứa các tệp tin cần lấy MD5:')
        self.edt_duong_dan.setText(ten_folder)
        self.edt_log.append(f'Đã chọn thư mục: {ten_folder}')
        return ten_folder

    # Hàm chức năng khi sự kiện khi ấn nút chọn tệp tin được thực hiện:
    def clicked_chon_tep_tin(self):
        ten_file = QFileDialog.getOpenFileName(self, 'Chọn tệp tin cần lấy MD5:')
        self.edt_duong_dan.setText(str(ten_file[0]))
        self.edt_log.append(f'Đã chọn tệp tin: {str(ten_file[0]).split("/")[-1]}')

    # Hàm chức năng khi sự kiện ấn nút sao chép tất cả được thực hiện
    def clicked_sao_chep(self):
        self.edt_ket_qua_hash.selectAll()
        self.edt_ket_qua_hash.copy()
        self.edt_log.append('Đã sao chép mã hash')

    def xoa_log(self):
        self.edt_log.clear()

    # Hàm tính mã Hash:
    def hash(self):
        duong_dan = self.edt_duong_dan.toPlainText()
        try:
            if os.path.isfile(duong_dan):
                self.lay_MD5_file(duong_dan)
            else:
                self.lay_MD5(duong_dan)
        except:
            QMessageBox.warning(self, 'Thông báo:', 'Chưa chọn đường dẫn đến file hoặc thư mục')
            self.edt_log.append('Chưa chọn đường dẫn đến file hoặc thư mục ---> Bấm chọn tệp tin hoặc thư mục')
            print('Chưa chọn đường dẫn đến file hoặc thư mục')

    # Hàm lấy mã MD5 của 01 file riêng lẻ:
    def lay_MD5_file(self, duong_dan):
        if os.path.isfile(duong_dan):
            ten_file = duong_dan.split("/")[-1]
            loai_ma = ''
            ma_hash = 0
            if self.rd_md5.isChecked():
                loai_ma = 'mã MD5'
                ma_hash = hashlib.md5(open(duong_dan, 'rb').read()).hexdigest()
            elif self.rd_sha1.isChecked():
                loai_ma = 'mã SHA1'
                ma_hash = hashlib.sha1(open(duong_dan, 'rb').read()).hexdigest()
            elif self.rd_sha256.isChecked():
                loai_ma = 'mã SHA256'
                ma_hash = hashlib.md5(open(duong_dan, 'rb').read()).hexdigest()
            dung_luong = self.dungluong(duong_dan)
            self.edt_ket_qua_hash.append(f'Tệp tin: {str(ten_file)}, {loai_ma}: {ma_hash}, dung lượng: {dung_luong} \n')
            self.edt_log.append(f'Đã thực hiện lấy {loai_ma} xong.')

    # Hàm lấy mã MD5 của tất cả các file có trong thư mục:
    # Phần này hơi dài và loằng ngoằng. Cần nghiên cứu viết lại.
    def lay_MD5(self, duong_dan):
        ds = os.listdir(duong_dan)
        so_tep_tin = 0
        for i in ds:
            dd_tuyet_doi = os.path.join(duong_dan, i)
            if os.path.isfile(dd_tuyet_doi):
                so_tep_tin += 1

        self.pb_progress_bar.setMaximum(so_tep_tin)

        dem = 1
        loai_ma = ''
        if self.rd_md5.isChecked():
            loai_ma = 'mã MD5'
        elif self.rd_sha1.isChecked():
            loai_ma = 'mã SHA1'
        elif self.rd_sha256.isChecked():
            loai_ma = 'mã SHA256'
        for i in ds:
            # Sử dụng đường dẫn tuyệt đối
            dd_tuyet_doi = os.path.join(duong_dan, i)
            print(dd_tuyet_doi)

            # Kiểm tra có phải là tập tin hay không:
            if os.path.isfile(dd_tuyet_doi):
                ma_hash_tep_tin = self.generate_file_hash(duong_dan, str(i), blocksize=2 ** 20)
                dung_luong = self.dungluong(dd_tuyet_doi)
                self.edt_ket_qua_hash.append(
                    f'- Tệp tin {dem}: {i}, {loai_ma}: {ma_hash_tep_tin}, dung lượng: {dung_luong}.\n')

                # Set giá trị progress bar:
                self.pb_progress_bar.setValue(dem)
                dem = dem + 1

                self.edt_log.append('Đang lấy mã MD5 tệp tin: ' + str(i))
        self.edt_log.append('.' * 60 + f'Đã thực hiện lấy {loai_ma} xong')
        self.edt_log.append('.' * 60 + f'Tổng cộng có: {dem - 1} tệp tin')

    # Hàm tính mã MD5 của file:
    def generate_file_hash(self, rootdir, filename, blocksize=2 ** 20):
        m = 0
        if self.rd_md5.isChecked():
            m = hashlib.md5()
        elif self.rd_sha1.isChecked():
            m = hashlib.sha1()
        elif self.rd_sha256.isChecked():
            m = hashlib.sha256()
        with open(os.path.join(rootdir, filename), "rb") as f:
            while True:
                buf = f.read(blocksize)
                if not buf:
                    break
                m.update(buf)
        return m.hexdigest()
################################################################################################################

    # Lấy dung lượng của tệp tin:
    def dungluong(self, duong_dan_file):
        # Lấy dung lượng theo byte của tệp tin:
        dungluong_byte = os.path.getsize(duong_dan_file)
        # nếu tệp tin có kích thước lớn hơn 1 MB:
        if dungluong_byte >= 1048576:
            dungluong_megabyte = dungluong_byte / 1048576
            return str(round(dungluong_megabyte, 1)).replace('.', ',') + ' MB'
        # Nếu tệp tin có kích thước nhỏ hơn 1KB:
        elif round(dungluong_byte / 1024) == 0:
            return str(dungluong_byte) + ' Bytes'
        # Còn lại nếu tệp tin có kích thước từ 1KB đến dưới 1MB:
        else:
            return str(round(dungluong_byte / 1024)).replace('.', ',') + ' KB'

    # Tab thông tin thuộc tính tệp tin:
    def xem_thong_tin(self):
        duong_dan = self.edt_duong_dan.toPlainText()
        if len(duong_dan) == 0:
            QMessageBox.warning(self, 'Thông báo:', 'Chưa chọn đường dẫn đến file hoặc thư mục')
            self.edt_log.append('Chưa chọn tệp tin ---> Bấm chọn tệp tin hoặc chọn thư mục')
        else:
            try:
                if os.path.isfile(duong_dan):
                    self.xem_thong_tin_mot_file(duong_dan)
                else:
                    pass
            except:
                pass

    def xem_thong_tin_mot_file(self, duong_dan_file):
        info = pymediainfo.MediaInfo.parse(duong_dan_file, output='JSON')
        du_lieu = json.loads(info)['media']['track'][0]
        du_lieu = json.dumps(du_lieu, indent=4, sort_keys=True)
        self.edt_ket_qua_thuoc_tinh.append(du_lieu)
        self.edt_log.append(f'Đã đọc thông tin thuộc tính của tệp: {duong_dan_file.split("/")[-1]}')

    def xoa(self):
        self.edt_ket_qua_thuoc_tinh.clear()
        self.edt_log.append('Đã xóa thông tin thuộc tính')

    def sao_chep_thuoc_tinh(self):
        self.edt_ket_qua_thuoc_tinh.selectAll()
        self.edt_ket_qua_thuoc_tinh.copy()
        self.edt_log.append('Đã sao chép thông tin thuộc tính')
#################################################################################################################

    def trich_frame(self):
        duong_dan = self.edt_duong_dan.toPlainText()
        if len(duong_dan) == 0:
            QMessageBox.warning(self, 'Thông báo:', 'Chưa chọn đường dẫn đến file hoặc thư mục')
            self.edt_log.append('Chưa chọn tệp tin ---> Bấm chọn tệp tin hoặc chọn thư mục')

            self.hyper_link('https://google.com')
        else:
            try:
                if os.path.isfile(duong_dan):
                    self.hyper_link(duong_dan)

                else:
                    pass
            except:
                pass

    def hyper_link(self, thu_muc_luu):
        self.tb_hyperlink.setReadOnly(True)
        self.tb_hyperlink.setOpenExternalLinks(True)
        self.tb_hyperlink.append(f"<a href={thu_muc_luu}>Thư mục lưu trữ các frames</a>")

    def conver_to_audio(self, duong_dan_file):
        video = moviepy.editor.VideoFileClip(duong_dan_file)
        print(f'Da doc file video {duong_dan_file}')
        audio = video.audio
        print('da chuyen thanh audio')
        audio.write_audiofile(self, 'converted.wav')
        print('Da ghi xong')

    def convert_audio_click(self):
        duong_dan = self.edt_duong_dan.toPlainText()
        if len(duong_dan) == 0:
            QMessageBox.warning(self, 'Thông báo:', 'Chưa chọn đường dẫn đến file hoặc thư mục')
            self.edt_log.append('Chưa chọn tệp tin ---> Bấm chọn tệp tin hoặc chọn thư mục')
        else:
            try:
                if os.path.isfile(duong_dan):
                    self.conver_to_audio(duong_dan)
                    print('Da convert xong..!')
                else:
                    pass
            except:
                pass


if __name__ == '__main__':
    app = QApplication(sys.argv)
    UIWindow = UI()
    sys.exit(app.exec_())
