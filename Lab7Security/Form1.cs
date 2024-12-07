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
                MessageBox.Show($"������� �����������: {ex.Message}", "�������", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void btnGenerateKeys_Click(object sender, EventArgs e)
        {
            try
            {
                // ����������� ������� ����
                rsaProvider = new RSACryptoServiceProvider();
                publicKey = rsaProvider.ToXmlString(false);
                string privateKey = rsaProvider.ToXmlString(true);

                txtPublicKey.Text = publicKey;
                txtPrivateKey.Text = privateKey;
                MessageBox.Show("���� ������ ������ �����������!", "����", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"������� ��������� ������: {ex.Message}", "�������", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void btnSignMessage_Click(object sender, EventArgs e)
        {
            try
            {
                byte[] message = Encoding.UTF8.GetBytes(txtMessage.Text);

                // ��������� ���-������� SHA-1
                using (SHA1 sha1 = new SHA1CryptoServiceProvider())
                {
                    byte[] messageHash = sha1.ComputeHash(message);

                    // ��������� ������
                    byte[] signature = rsaProvider.SignHash(messageHash, "sha1");

                    txtSignature.Text = Convert.ToBase64String(signature);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"������� �����������: {ex.Message}", "�������", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void btnVerifySignature_Click(object sender, EventArgs e)
        {
            try
            {
                byte[] message = Encoding.UTF8.GetBytes(txtVerifyMessage.Text);
                byte[] signature = Convert.FromBase64String(txtVerifySignature.Text);

                // ��������� ���-������� SHA-1
                using (SHA1 sha1 = new SHA1CryptoServiceProvider())
                {
                    byte[] messageHash = sha1.ComputeHash(message);

                    // ��������� ����������� RSA ���������� � �������� ������
                    using (RSACryptoServiceProvider tempRsa = new RSACryptoServiceProvider())
                    {
                        tempRsa.FromXmlString(txtVerifyPublicKey.Text);

                        // �������� ������
                        bool isValid = tempRsa.VerifyHash(messageHash, "sha1", signature);

                        MessageBox.Show(isValid ? "ϳ���� ������!" : "ϳ���� ��������!",
                            "��������� ��������",
                            MessageBoxButtons.OK,
                            isValid ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"������� �������� ������: {ex.Message}", "�������", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void InitializeComponent()
        {
            this.Text = "RSA �������� ϳ����";
            this.Size = new System.Drawing.Size(600, 700);

            // ������� ��������� ������
            TabControl tabControl = new TabControl();
            tabControl.Dock = DockStyle.Fill;

            TabPage keyGenerationTab = new TabPage("��������� ������");
            TabPage signingTab = new TabPage("ϳ����������");
            TabPage verificationTab = new TabPage("��������");

            // ���������� ������� ��������� ������
            Button btnGenerateKeys = new Button
            {
                Text = "����������� �����",
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
                Text = "�������� ����:",
                Dock = DockStyle.Top
            };

            Label lblPrivateKey = new Label
            {
                Text = "��������� ����:",
                Dock = DockStyle.Top
            };

            keyGenerationTab.Controls.AddRange(new Control[] {
                btnGenerateKeys,
                txtPublicKey,
                lblPublicKey,
                txtPrivateKey,
                lblPrivateKey
            });

            // ���������� ������� �����������
             txtMessage = new TextBox
            {
                Multiline = true,
                Height = 150,
                Dock = DockStyle.Top
            };

            Button btnSignMessage = new Button
            {
                Text = "ϳ������� �����������",
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

            Label lblMessage = new Label { Text = "�����������:", Dock = DockStyle.Top };
            Label lblSignature = new Label { Text = "�������� �����:", Dock = DockStyle.Top };

            signingTab.Controls.AddRange(new Control[] {
                btnSignMessage,
                txtSignature,
                lblSignature,
                txtMessage,
                lblMessage,
            });

            // ���������� ������� ��������
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
                Text = "��������� �����",
                Dock = DockStyle.Top,
                Height = 30,
            };
            btnVerifySignature.Click += btnVerifySignature_Click;

            Label lblVerifyMessage = new Label { Text = "�����������:", Dock = DockStyle.Top };
            Label lblVerifyPublicKey = new Label { Text = "�������� ����:", Dock = DockStyle.Top };
            Label lblVerifySignature = new Label { Text = "�������� �����:", Dock = DockStyle.Top };

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
