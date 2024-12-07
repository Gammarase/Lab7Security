using System.Text;
using System.Security.Cryptography;

namespace Lab7Security
{
    public partial class Form1 : Form
    {
        private RSACryptoServiceProvider rsaProvider;
        private string publicKey;

        public Form1()
        {
            InitializeRSAProvider();
            InitializeComponent();
        }

        private void InitializeRSAProvider()
        {
            try
            {
                CspParameters cspParams = new CspParameters
                {
                    KeyContainerName = "UserKeyContainer"
                };
                rsaProvider = new RSACryptoServiceProvider(cspParams);
                publicKey = rsaProvider.ToXmlString(false);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Помилка ініціалізації: {ex.Message}", "Помилка", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void btnGenerateKeys_Click(object sender, EventArgs e)
        {
            try
            {
                // Регенерація ключової пари
                rsaProvider = new RSACryptoServiceProvider();
                publicKey = rsaProvider.ToXmlString(false);
                string privateKey = rsaProvider.ToXmlString(true);

                txtPublicKey.Text = publicKey;
                txtPrivateKey.Text = privateKey;
                MessageBox.Show("Пара ключів успішно згенерована!", "Успіх", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Помилка генерації ключів: {ex.Message}", "Помилка", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void btnSignMessage_Click(object sender, EventArgs e)
        {
            try
            {
                byte[] message = Encoding.UTF8.GetBytes(txtMessage.Text);

                // Створення геш-функції SHA-1
                using (SHA1 sha1 = new SHA1CryptoServiceProvider())
                {
                    byte[] messageHash = sha1.ComputeHash(message);

                    // Створення підпису
                    byte[] signature = rsaProvider.SignHash(messageHash, "sha1");

                    txtSignature.Text = Convert.ToBase64String(signature);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Помилка підписування: {ex.Message}", "Помилка", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void btnVerifySignature_Click(object sender, EventArgs e)
        {
            try
            {
                byte[] message = Encoding.UTF8.GetBytes(txtVerifyMessage.Text);
                byte[] signature = Convert.FromBase64String(txtVerifySignature.Text);

                // Створення геш-функції SHA-1
                using (SHA1 sha1 = new SHA1CryptoServiceProvider())
                {
                    byte[] messageHash = sha1.ComputeHash(message);

                    // Створення тимчасового RSA провайдера з публічним ключем
                    using (RSACryptoServiceProvider tempRsa = new RSACryptoServiceProvider())
                    {
                        tempRsa.FromXmlString(txtVerifyPublicKey.Text);

                        // Перевірка підпису
                        bool isValid = tempRsa.VerifyHash(messageHash, "sha1", signature);

                        MessageBox.Show(isValid ? "Підпис дійсний!" : "Підпис недійсний!",
                            "Результат перевірки",
                            MessageBoxButtons.OK,
                            isValid ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Помилка перевірки підпису: {ex.Message}", "Помилка", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void InitializeComponent()
        {
            this.Text = "RSA Цифровий Підпис";
            this.Size = new System.Drawing.Size(600, 700);

            // Вкладка генерації ключів
            TabControl tabControl = new TabControl();
            tabControl.Dock = DockStyle.Fill;

            TabPage keyGenerationTab = new TabPage("Генерація Ключів");
            TabPage signingTab = new TabPage("Підписування");
            TabPage verificationTab = new TabPage("Перевірка");

            // Компоненти вкладки генерації ключів
            Button btnGenerateKeys = new Button
            {
                Text = "Згенерувати ключі",
                Dock = DockStyle.Top,
                Height = 30
            };
            btnGenerateKeys.Click += btnGenerateKeys_Click;

             txtPublicKey = new TextBox
            {
                Multiline = true,
                Height = 200,
                Dock = DockStyle.Top,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical
            };

             txtPrivateKey = new TextBox
            {
                Multiline = true,
                Height = 200,
                Dock = DockStyle.Top,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical
            };

            Label lblPublicKey = new Label
            {
                Text = "Публічний ключ:",
                Dock = DockStyle.Top
            };

            Label lblPrivateKey = new Label
            {
                Text = "Приватний ключ:",
                Dock = DockStyle.Top
            };

            keyGenerationTab.Controls.AddRange(new Control[] {
                btnGenerateKeys,
                txtPublicKey,
                lblPublicKey,
                txtPrivateKey,
                lblPrivateKey
            });

            // Компоненти вкладки підписування
             txtMessage = new TextBox
            {
                Multiline = true,
                Height = 150,
                Dock = DockStyle.Top
            };

            Button btnSignMessage = new Button
            {
                Text = "Підписати повідомлення",
                Dock = DockStyle.Top,
                Height = 30,
            };
            btnSignMessage.Click += btnSignMessage_Click;

             txtSignature = new TextBox
            {
                Multiline = true,
                Height = 150,
                Dock = DockStyle.Top,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical
            };

            Label lblMessage = new Label { Text = "Повідомлення:", Dock = DockStyle.Top };
            Label lblSignature = new Label { Text = "Цифровий підпис:", Dock = DockStyle.Top };

            signingTab.Controls.AddRange(new Control[] {
                btnSignMessage,
                txtSignature,
                lblSignature,
                txtMessage,
                lblMessage,
            });

            // Компоненти вкладки перевірки
             txtVerifyMessage = new TextBox
            {
                Multiline = true,
                Height = 150,
                Dock = DockStyle.Top
            };

             txtVerifyPublicKey = new TextBox
            {
                Multiline = true,
                Height = 150,
                Dock = DockStyle.Top,
                ScrollBars = ScrollBars.Vertical
            };

             txtVerifySignature = new TextBox
            {
                Multiline = true,
                Height = 150,
                Dock = DockStyle.Top,
                ScrollBars = ScrollBars.Vertical
            };

            Button btnVerifySignature = new Button
            {
                Text = "Перевірити підпис",
                Dock = DockStyle.Top,
                Height = 30,
            };
            btnVerifySignature.Click += btnVerifySignature_Click;

            Label lblVerifyMessage = new Label { Text = "Повідомлення:", Dock = DockStyle.Top };
            Label lblVerifyPublicKey = new Label { Text = "Публічний ключ:", Dock = DockStyle.Top };
            Label lblVerifySignature = new Label { Text = "Цифровий підпис:", Dock = DockStyle.Top };

            verificationTab.Controls.AddRange(new Control[] {
                btnVerifySignature,
                txtVerifyPublicKey,
                lblVerifyPublicKey,
                txtVerifySignature,
                lblVerifySignature,
                txtVerifyMessage,
                lblVerifyMessage,
            });

            tabControl.TabPages.AddRange(new TabPage[] {
                keyGenerationTab,
                signingTab,
                verificationTab
            });

            this.Controls.Add(tabControl);
        }
        private TextBox txtPublicKey;
        private TextBox txtPrivateKey;
        private TextBox txtMessage;
        private TextBox txtSignature;
        private TextBox txtVerifyMessage;
        private TextBox txtVerifySignature;
        private TextBox txtVerifyPublicKey;


    }
}
