using System.Text;
using System.Windows;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Win32;
using System.Windows.Controls;
using System.Windows.Input;

namespace AES
{
	/// <summary>
	/// Interaction logic for MainWindow.xaml
	/// </summary>
	public partial class MainWindow : Window
	{
		public MainWindow()
		{
			InitializeComponent();
		}

		//phương thức trả về kích thước khóa
		private int GetKeySize(bool isEncryption)
		{
			if (isEncryption) // mã hóa
			{
				if (rdb_en_128.IsChecked == true) 
					return 128;
				if (rdb_en_192.IsChecked == true) 
					return 192;
				if (rdb_en_256.IsChecked == true)
					return 256;
			}
			else // giải mã
			{
				if (rdb_de_128.IsChecked == true) 
					return 128;
				if (rdb_de_192.IsChecked == true) 
					return 192;
				if (rdb_de_256.IsChecked == true) 
					return 256;
			}
			return 128;
		}

		// phương thức chuyển khóa từ text sang mảng byte
		private byte[] GetKeyFromInput(string keyInput, int keySize)
		{
			byte[] key = Encoding.UTF8.GetBytes(keyInput);

			// nếu khóa không đạt đủ kích thước sẽ được bổ sung thêm các byte 0x00 cho đủ kích thước yêu cầu
			if (key.Length < keySize / 8) 
			{
				Array.Resize(ref key, keySize / 8);
			}
			return key;
		}

		// phương thức mã hóa
		private byte[] Encrypt(string plainText, byte[] key)
		{
			using (Aes aes = Aes.Create())
			{
				aes.Key = key;
				aes.GenerateIV();
				aes.Mode = CipherMode.CBC;
				aes.Padding = PaddingMode.PKCS7;

				using (ICryptoTransform encryptor = aes.CreateEncryptor())
				using (MemoryStream ms = new MemoryStream())
				{
					ms.Write(aes.IV, 0, aes.IV.Length); // Ghi IV vào đầu dữ liệu mã hóa
					using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
					{
						byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);
						cs.Write(inputBytes, 0, inputBytes.Length);
						cs.FlushFinalBlock();
					}
					return ms.ToArray();
				}
			}
		}

		// phương thức giải mã
		private string Decrypt(byte[] cipherText, byte[] key)
		{
			using (Aes aes = Aes.Create())
			{
				aes.Key = key;
				aes.Mode = CipherMode.CBC;
				aes.Padding = PaddingMode.PKCS7;

				using (MemoryStream ms = new MemoryStream(cipherText))
				{
					byte[] iv = new byte[16]; // AES IV có độ dài cố định là 16 bytes
					ms.Read(iv, 0, iv.Length);
					aes.IV = iv;

					using (ICryptoTransform decryptor = aes.CreateDecryptor())
					using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
					using (StreamReader sr = new StreamReader(cs, Encoding.UTF8))
					{
						return sr.ReadToEnd();
					}
				}
			}
		}

		// phương thức kiểm tra dữ liệu trước khi tiến hành mã hóa/giải mã
		private bool Check_empty(bool isEncryption)
		{
			if (isEncryption)
			{
				if (txt_en_ban_ro.Text == "")
				{
					MessageBox.Show("Bạn chưa nhập bản rõ!", "Error",
						MessageBoxButton.OK, MessageBoxImage.Error);
					txt_en_ban_ro.Focus();
					return false;
				}

				if (txt_en_key.Text == "")
				{
					MessageBox.Show("Bạn chưa nhập khóa mã hóa!", "Error",
						MessageBoxButton.OK, MessageBoxImage.Error);
					txt_en_key.Focus();
					return false;
				}

				if (txt_en_key.Text.Length > (GetKeySize(true) / 8))
				{
					MessageBox.Show($"Kích thước khóa mã hóa không được vượt quá {GetKeySize(true)} bits ({(GetKeySize(true) / 8)} ký tự) bạn đã chọn trước đó!", 
						"Error", MessageBoxButton.OK, MessageBoxImage.Error);
					txt_en_key.Focus();
					return false;
				}
			}
			else
			{
				if (txt_de_ban_ma.Text == "")
				{
					MessageBox.Show("Bạn chưa nhập bản mã!", "Error",
						MessageBoxButton.OK, MessageBoxImage.Error);
					txt_de_ban_ma.Focus();
					return false;
				}

				if (txt_de_key.Text == "")
				{
					MessageBox.Show("Bạn chưa nhập khóa giải mã!", "Error", 
						MessageBoxButton.OK, MessageBoxImage.Error);
					txt_de_key.Focus();
					return false;
				}

				if (txt_de_key.Text.Length > (GetKeySize(false) / 8))
				{
					MessageBox.Show($"Kích thước khóa giải mã không được vượt quá {GetKeySize(false)} bits ({(GetKeySize(false) / 8)} ký tự) bạn đã chọn trước đó!",
						"Error", MessageBoxButton.OK, MessageBoxImage.Error);
					txt_de_key.Focus();
					return false;
				}
			}
			return true;
		}

		private void btn_mahoa_Click(object sender, RoutedEventArgs e)
		{
			try
			{
				if (Check_empty(true))
				{
					string plainText = txt_en_ban_ro.Text;
					int keySize = GetKeySize(true);
					byte[] key = GetKeyFromInput(txt_en_key.Text, keySize);

					byte[] cipherText = Encrypt(plainText, key);
					txt_en_ban_ma.Text = Convert.ToBase64String(cipherText);

					MessageBox.Show("Mã hóa thành công!", "Mã hóa",
					MessageBoxButton.OK, MessageBoxImage.Information);
				}
			}
			catch
			{
				MessageBox.Show("Có lỗi trong quá trình mã hóa!", "Error", 
					MessageBoxButton.OK, MessageBoxImage.Error);
			}
		}

		private void btn_giai_ma_Click(object sender, RoutedEventArgs e)
		{
			try
			{
				if (Check_empty(false))
				{
					byte[] cipherText = Convert.FromBase64String(txt_de_ban_ma.Text);
					int keySize = GetKeySize(false);
					byte[] key = GetKeyFromInput(txt_de_key.Text, keySize);

					string plainText = Decrypt(cipherText, key);
					txt_de_ban_ro.Text = plainText;

					MessageBox.Show("Giải mã thành công!", "Giải mã",
					MessageBoxButton.OK, MessageBoxImage.Information);
				}
			}
			catch
			{
				MessageBox.Show("Không thể giải mã, bản mã hoặc khóa giải mã không chính xác!", 
					"Error", MessageBoxButton.OK, MessageBoxImage.Error);
			}
		}

		// phương thức mở tệp
		private void OpenFile(TextBox targetTextBox) 
		{ 
			try 
			{ 
				OpenFileDialog openFileDialog = new OpenFileDialog 
				{
					Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*" 
				}; 
				if (openFileDialog.ShowDialog() == true) 
				{
					string fileContent = File.ReadAllText(openFileDialog.FileName); 
					targetTextBox.Text = fileContent; 
				} 
			}
			catch
			{
				MessageBox.Show("Có lỗi trong quá trinh mở tệp!", "Error",
					MessageBoxButton.OK, MessageBoxImage.Error);
			}
		
		}

		private void btn_en_file_Click(object sender, RoutedEventArgs e)
		{
			OpenFile(txt_en_ban_ro);
		}

		private void btn_de_file_Click(object sender, RoutedEventArgs e)
		{
			OpenFile(txt_en_ban_ma);
		}

		// phương thức lưu tệp
		private void SaveToFile(string content)
		{
			try
			{
				SaveFileDialog saveFileDialog = new SaveFileDialog
				{
					Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*"
				};

				if (saveFileDialog.ShowDialog() == true)
				{
					File.WriteAllText(saveFileDialog.FileName, content);
					MessageBox.Show("Lưu tệp thành công!", "Thông báo", 
						MessageBoxButton.OK, MessageBoxImage.Information);
				}
			}
			catch
			{
				MessageBox.Show("Có lỗi trong quá trình lưu tệp!", "Error",
					MessageBoxButton.OK, MessageBoxImage.Error);
			}
		}

		private void btn_en_luu_tep_Click(object sender, RoutedEventArgs e)
		{
			SaveToFile(txt_en_ban_ma.Text);
		}

		private void btn_de_luu_tep_Click(object sender, RoutedEventArgs e)
		{
			SaveToFile(txt_de_ban_ro.Text);
		}


		// MÃ HÓA VÀ GIẢI MÃ FILE
		private void btn_mo_file_Click(object sender, RoutedEventArgs e)
		{
			OpenFileDialog openFileDialog = new OpenFileDialog
			{Filter = "All Files (*.*)|*.*"};

			if (openFileDialog.ShowDialog() == true)
			{
				txt_file_path.Text = openFileDialog.FileName;
			}
		}

		// Kiểm tra độ dài khóa
		private bool ValidateKeyLength(string key)
		{
			int keyLength = key.Length * 8; 
			return keyLength == 128 || keyLength == 192 || keyLength == 256;
		}

		// Lấy kích thước khóa theo lựa chọn (128, 192, hoặc 256 bit)
		private int GetKeyLengthInBytes()
		{
			if (rdb_file_128.IsChecked == true)
				return 16;
			if (rdb_file_192.IsChecked == true)
				return 24;
			if (rdb_file_256.IsChecked == true)
				return 32;

			throw new InvalidOperationException("Vui lòng chọn kích thước khóa!");
		}

		// Kiểm tra và tự động điều chỉnh độ dài khóa
		private string AdjustKeyLength(string key, int requiredLength)
		{
			if (key.Length < requiredLength)
				key = key.PadRight(requiredLength, '0');// Bổ sung thêm ký tự '0' để đạt độ dài cần thiết
			return key;
		}

		// Mã hóa file
		private byte[] EncryptFile(byte[] fileBytes, string key)
		{
			using (Aes aes = Aes.Create())
			{
				int requiredKeyLength = GetKeyLengthInBytes(); 
				key = AdjustKeyLength(key, requiredKeyLength); 
				aes.Key = Encoding.UTF8.GetBytes(key);
				aes.IV = new byte[16];

				using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
				{
					return PerformCryptography(fileBytes, encryptor);
				}
			}
		}

		// Giải mã file
		private byte[] DecryptFile(byte[] fileBytes, string key)
		{
			using (Aes aes = Aes.Create())
			{
				int requiredKeyLength = GetKeyLengthInBytes();
				key = AdjustKeyLength(key, requiredKeyLength);
				aes.Key = Encoding.UTF8.GetBytes(key);
				aes.IV = new byte[16]; 

				using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
				{
					return PerformCryptography(fileBytes, decryptor);
				}
			}
		}

		// Thực hiện mã hóa/giải mã
		private byte[] PerformCryptography(byte[] inputBytes, ICryptoTransform cryptoTransform)
		{
			using (MemoryStream memoryStream = new MemoryStream())
			{
				using (CryptoStream cryptoStream = new CryptoStream
					(memoryStream, cryptoTransform, CryptoStreamMode.Write))
				{
					cryptoStream.Write(inputBytes, 0, inputBytes.Length);
					cryptoStream.FlushFinalBlock();
					return memoryStream.ToArray();
				}
			}
		}

		private int GetKeySize_file()
		{
			if (rdb_file_128.IsChecked == true)
				return 128;
			if (rdb_file_192.IsChecked == true)
				return 192;
			if (rdb_file_256.IsChecked == true)
				return 256;
			
			return 128;
		}

		private bool Check_file_and_key()
		{
			if (string.IsNullOrEmpty(txt_file_path.Text))
			{
				MessageBox.Show("Vui lòng chọn file trước khi mã hóa/giải mã!", "Thông báo",
					MessageBoxButton.OK, MessageBoxImage.Error);
				return false;
			}
			if (!File.Exists(txt_file_path.Text))
			{
				MessageBox.Show("Tệp tin không tồn tại hoặc bị sai đường dẫn.\nVui lòng chọn tệp tin khác!",
					"Thông báo", MessageBoxButton.OK, MessageBoxImage.Error);
				return false;
			}
			if (string.IsNullOrEmpty(txt_file_key.Text))
			{
				MessageBox.Show("Vui lòng nhập khóa trước khi mã hóa/giải mã!", "Thông báo",
					MessageBoxButton.OK, MessageBoxImage.Error);
				return false;
			}
			if (txt_file_key.Text.Length > (GetKeySize(false) / 8))
			{
				MessageBox.Show($"Kích thước khóa mã hóa/giải mã không được vượt quá {GetKeySize_file()} bits ({(GetKeySize_file() / 8)} ký tự) bạn đã chọn trước đó!",
					"Error", MessageBoxButton.OK, MessageBoxImage.Error);
				txt_file_key.Focus();
				return false;
			}
			return true;
		}

		private void btn_ma_hoa_file_Click(object sender, RoutedEventArgs e)
		{
			if (Check_file_and_key())
			{
				try
				{
					byte[] fileBytes = File.ReadAllBytes(txt_file_path.Text);
					byte[] encryptedBytes = EncryptFile(fileBytes, txt_file_key.Text);
					MessageBoxResult r = MessageBox.Show("Mã hóa thành công, hãy chọn vị trí lưu file mã hóa!",
						"Thông báo", MessageBoxButton.OK, MessageBoxImage.Information);
					SaveFile(encryptedBytes, "encrypted");
				}
				catch
				{
					MessageBox.Show("Có lỗi trong quá trình mã hóa file!", "Lỗi",
						MessageBoxButton.OK, MessageBoxImage.Error);
				}
			}
		}

		private void btn_giai_ma_file_Click(object sender, RoutedEventArgs e)
		{
			if (Check_file_and_key())
			{
				try
				{
					byte[] fileBytes = File.ReadAllBytes(txt_file_path.Text);
					byte[] decryptedBytes = DecryptFile(fileBytes, txt_file_key.Text);
					MessageBoxResult r = MessageBox.Show("Giải mã thành công, hãy chọn vị trí lưu file giải mã!",
						"Thông báo", MessageBoxButton.OK, MessageBoxImage.Information);
					SaveFile(decryptedBytes, "decrypted");
				}
				catch
				{
					MessageBox.Show("Không thể giải mã, file bản mã hoặc khóa giải mã không chính xác!",
					"Error", MessageBoxButton.OK, MessageBoxImage.Error);
				}
			}
		}

		// Lưu file sau khi mã hóa/giải mã
		private void SaveFile(byte[] fileBytes, string action)
		{
			SaveFileDialog saveFileDialog = new SaveFileDialog
			{
				Filter = "All Files (*.*)|*.*",
				FileName = $"{Path.GetFileNameWithoutExtension(txt_file_path.Text)}_{action}{Path.GetExtension(txt_file_path.Text)}"
			};

			if (saveFileDialog.ShowDialog() == true)
			{
				File.WriteAllBytes(saveFileDialog.FileName, fileBytes);
				MessageBox.Show($"Lưu file thành công!", "Thông báo", 
					MessageBoxButton.OK, MessageBoxImage.Information);
			}
		}

		private void btn_refresh_Click(object sender, RoutedEventArgs e)
		{
			txt_en_ban_ro.Text = string.Empty;
			txt_en_ban_ma.Text = string.Empty;
			txt_en_key.Text = string.Empty;
			rdb_en_128.IsChecked = true;

			txt_de_ban_ro.Text = string.Empty;
			txt_de_ban_ma.Text = string.Empty;
			txt_de_key.Text = string.Empty;
			rdb_de_128.IsChecked = true;

			txt_file_path.Text = string.Empty;
			txt_file_key.Text = string.Empty;
		}

		private void btn_thoat_Click(object sender, RoutedEventArgs e)
		{
			MessageBoxResult r = MessageBox.Show("Bạn muốn thoát chương trình?", "Exit",
				MessageBoxButton.YesNo, MessageBoxImage.Question);
			if (r == MessageBoxResult.Yes)
				Close();
		}
	}
}