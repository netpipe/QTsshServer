#include <QApplication>
#include <QWidget>
#include <QFormLayout>
#include <QLineEdit>
#include <QCheckBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QFile>
#include <QTextStream>
#include <QMessageBox>
#include <QLabel>
#include <QFileDialog>
#include <QProcess>
#include <QGroupBox>
#include <QVBoxLayout>

class SshdConfigEditor : public QWidget {
    Q_OBJECT
public:
    explicit SshdConfigEditor(QWidget *parent = nullptr) : QWidget(parent) {
        setWindowTitle("sshd Config Editor and Runner");

        QVBoxLayout *mainLayout = new QVBoxLayout(this);

        QFormLayout *layout = new QFormLayout();

        // Config path
        configPathEdit = new QLineEdit(this);
        configPathEdit->setText("sshd_custom_config");
        QPushButton *browseBtn = new QPushButton("Browse", this);
        QHBoxLayout *configPathLayout = new QHBoxLayout();
        configPathLayout->addWidget(configPathEdit);
        configPathLayout->addWidget(browseBtn);
        mainLayout->addLayout(configPathLayout);

        connect(browseBtn, &QPushButton::clicked, this, &SshdConfigEditor::browseConfigFile);

        // Port
        portEdit = new QLineEdit(this);
        layout->addRow("Port:", portEdit);

        // PermitRootLogin
        permitRootLoginCheck = new QCheckBox("Permit root login (prohibit-password)", this);
        layout->addRow("", permitRootLoginCheck);

        // KbdInteractiveAuthentication
        kbdInteractiveCheck = new QCheckBox("Enable Keyboard-Interactive Authentication", this);
        layout->addRow("", kbdInteractiveCheck);

        // Allowed IPs (ListenAddress)
        allowedIPsEdit = new QPlainTextEdit(this);
        allowedIPsEdit->setPlaceholderText("Allowed IPs (one per line, e.g. 192.168.1.0/24)");
        layout->addRow(new QLabel("Allowed IPs:"), allowedIPsEdit);

        // LoginGraceTime
        loginGraceEdit = new QLineEdit(this);
        layout->addRow("LoginGraceTime (e.g. 2m):", loginGraceEdit);

        // MaxAuthTries
        maxAuthTriesEdit = new QLineEdit(this);
        layout->addRow("MaxAuthTries:", maxAuthTriesEdit);

        // MaxSessions
        maxSessionsEdit = new QLineEdit(this);
        layout->addRow("MaxSessions:", maxSessionsEdit);

        // Username
        usernameEdit = new QLineEdit(this);
        layout->addRow("Username:", usernameEdit);

        // Password (just UX, not stored in config)
        passwordEdit = new QLineEdit(this);
        passwordEdit->setEchoMode(QLineEdit::Password);
        layout->addRow("Password (not stored):", passwordEdit);

        // No password checkbox disables password login
        noPasswordCheck = new QCheckBox("Disable Password Authentication (use keyboard-interactive or keys)", this);
        layout->addRow("", noPasswordCheck);

        mainLayout->addLayout(layout);

        // Buttons
        QHBoxLayout *btnLayout = new QHBoxLayout();
        loadBtn = new QPushButton("Load Config", this);
        saveBtn = new QPushButton("Save Config", this);
        startBtn = new QPushButton("Start sshd", this);
        stopBtn = new QPushButton("Stop sshd", this);
        stopBtn->setEnabled(false);

        btnLayout->addWidget(loadBtn);
        btnLayout->addWidget(saveBtn);
        btnLayout->addWidget(startBtn);
        btnLayout->addWidget(stopBtn);
        mainLayout->addLayout(btnLayout);

        // Output
        outputEdit = new QPlainTextEdit(this);
        outputEdit->setReadOnly(true);
        outputEdit->setPlaceholderText("sshd process output and errors...");
        mainLayout->addWidget(outputEdit);

        sshdProcess = new QProcess(this);


        // Key-based auth
        authorizedKeysEdit = new QLineEdit(this);
        authorizedKeysEdit->setText(QDir::homePath() + "/.ssh/authorized_keys");
        layout->addRow("AuthorizedKeysFile:", authorizedKeysEdit);

        pubkeyAuthCheck = new QCheckBox("Enable Public Key Authentication", this);
        layout->addRow("", pubkeyAuthCheck);

        genKeyBtn = new QPushButton("Generate SSH Key", this);
        viewKeyBtn = new QPushButton("View Public Key", this);
        authKeyBtn = new QPushButton("Authorize Public Key", this);

        QHBoxLayout *keyBtnLayout = new QHBoxLayout();
        keyBtnLayout->addWidget(genKeyBtn);
        keyBtnLayout->addWidget(viewKeyBtn);
        keyBtnLayout->addWidget(authKeyBtn);
        mainLayout->addLayout(keyBtnLayout);

        connect(genKeyBtn, &QPushButton::clicked, this, &SshdConfigEditor::generateKey);
        connect(viewKeyBtn, &QPushButton::clicked, this, &SshdConfigEditor::viewPublicKey);
        connect(authKeyBtn, &QPushButton::clicked, this, &SshdConfigEditor::authorizePublicKey);


        connect(loadBtn, &QPushButton::clicked, this, &SshdConfigEditor::loadConfig);
        connect(saveBtn, &QPushButton::clicked, this, &SshdConfigEditor::saveConfig);
        connect(startBtn, &QPushButton::clicked, this, &SshdConfigEditor::startSshd);
        connect(stopBtn, &QPushButton::clicked, this, &SshdConfigEditor::stopSshd);
        connect(sshdProcess, &QProcess::readyReadStandardOutput, this, &SshdConfigEditor::readSshdOutput);
        connect(sshdProcess, &QProcess::readyReadStandardError, this, &SshdConfigEditor::readSshdError);
        connect(sshdProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                this, &SshdConfigEditor::sshdFinished);

        loadConfig();
    }

private slots:
    void browseConfigFile() {
        QString file = QFileDialog::getOpenFileName(this, "Open sshd config file", QString(), "Config files (*.*)");
        if (!file.isEmpty()) {
            configPathEdit->setText(file);
            loadConfig();
        }
    }
    void generateKey() {
        QString privKey = QDir::homePath() + "/.ssh/id_ed25519";
        if (QFile::exists(privKey)) {
            QMessageBox::StandardButton reply = QMessageBox::question(this, "Key Exists",
                "SSH key already exists. Overwrite?", QMessageBox::Yes|QMessageBox::No);
            if (reply == QMessageBox::No)
                return;
        }
        QProcess::execute("ssh-keygen", {"-t", "ed25519", "-f", privKey, "-N", ""});
        QMessageBox::information(this, "Done", "SSH key generated at:\n" + privKey);
    }

    void viewPublicKey() {
        QString pubKey = QDir::homePath() + "/.ssh/id_ed25519.pub";
        QFile f(pubKey);
        if (!f.exists() || !f.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QMessageBox::warning(this, "Missing Key", "Public key not found:\n" + pubKey);
            return;
        }
        QTextStream in(&f);
        QString key = in.readAll();
        f.close();
        QMessageBox::information(this, "Public Key", key);
    }

    void authorizePublicKey() {
        QString pubKey = QDir::homePath() + "/.ssh/id_ed25519.pub";
        QFile f(pubKey);
        if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QMessageBox::warning(this, "Missing", "Public key not found:\n" + pubKey);
            return;
        }
        QString key = f.readAll().trimmed();
        f.close();

        QString authFile = authorizedKeysEdit->text();
        QFile af(authFile);
        if (!af.open(QIODevice::Append | QIODevice::Text)) {
            QMessageBox::warning(this, "Error", "Could not open authorized_keys to append:\n" + authFile);
            return;
        }
        QTextStream out(&af);
        out << key << "\n";
        af.close();

        QMessageBox::information(this, "Success", "Key added to:\n" + authFile);
    }

    void loadConfig() {
        QString filePath = configPathEdit->text();
        QFile f(filePath);
        if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QMessageBox::warning(this, "Error", "Could not open config file for reading:\n" + filePath);
            return;
        }
        QTextStream in(&f);

        // Clear fields
        portEdit->clear();
        permitRootLoginCheck->setChecked(false);
        kbdInteractiveCheck->setChecked(false);
        allowedIPsEdit->clear();
        loginGraceEdit->clear();
        maxAuthTriesEdit->clear();
        maxSessionsEdit->clear();
        usernameEdit->clear();
        passwordEdit->clear();
        noPasswordCheck->setChecked(false);

        while (!in.atEnd()) {
            QString line = in.readLine().trimmed();
            if (line.isEmpty() || line.startsWith('#'))
                continue;

            if (line.startsWith("Port ")) {
                portEdit->setText(line.section(' ', 1,1));
            } else if (line.startsWith("PermitRootLogin ")) {
                QString val = line.section(' ', 1,1);
                permitRootLoginCheck->setChecked(val == "prohibit-password" || val == "yes");
            } else if (line.startsWith("KbdInteractiveAuthentication ")) {
                QString val = line.section(' ', 1,1);
                kbdInteractiveCheck->setChecked(val.toLower() == "yes");
            } else if (line.startsWith("LoginGraceTime ")) {
                loginGraceEdit->setText(line.section(' ',1,1));
            } else if (line.startsWith("MaxAuthTries ")) {
                maxAuthTriesEdit->setText(line.section(' ',1,1));
            } else if (line.startsWith("MaxSessions ")) {
                maxSessionsEdit->setText(line.section(' ',1,1));
            } else if (line.startsWith("AllowUsers ")) {
                QString users = line.section(' ', 1);
                QStringList userList = users.split(' ');
                if (!userList.isEmpty()) {
                    QString first = userList[0];
                    if (first.contains('@')) {
                        usernameEdit->setText(first.section('@', 0, 0));

                        QStringList ips;
                        for (const QString &u : userList) {
                            ips << u.section('@', 1, 1);
                        }
                        allowedIPsEdit->setPlainText(ips.join("\n"));

                    } else {
                        usernameEdit->setText(first);
                    }
                }
            } else if (line.startsWith("PasswordAuthentication ")) {
                QString val = line.section(' ',1,1);
                noPasswordCheck->setChecked(val.toLower() == "no");
            } else if (line.startsWith("ListenAddress ")) {
                allowedIPsEdit->appendPlainText(line.section(' ',1,1));
            }
        }
        f.close();
    }

    void saveConfig() {
        QString filePath = configPathEdit->text();
        QFile f(filePath);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QMessageBox::warning(this, "Error", "Could not open config file for writing:\n" + filePath);
            return;
        }
        QTextStream out(&f);

        out << "# sshd Custom Config\n";
        out << "Port " << (portEdit->text().isEmpty() ? "22" : portEdit->text()) << "\n";

        if (permitRootLoginCheck->isChecked()) {
            out << "PermitRootLogin prohibit-password\n";
        } else {
            out << "#PermitRootLogin prohibit-password\n";
        }

        out << "KbdInteractiveAuthentication " << (kbdInteractiveCheck->isChecked() ? "yes" : "no") << "\n";
        out << "LoginGraceTime " << (loginGraceEdit->text().isEmpty() ? "2m" : loginGraceEdit->text()) << "\n";
        out << "MaxAuthTries " << (maxAuthTriesEdit->text().isEmpty() ? "6" : maxAuthTriesEdit->text()) << "\n";
        out << "MaxSessions " << (maxSessionsEdit->text().isEmpty() ? "10" : maxSessionsEdit->text()) << "\n";
        out << "AuthorizedKeysFile " << authorizedKeysEdit->text() << "\n";
        out << "PubkeyAuthentication " << (pubkeyAuthCheck->isChecked() ? "yes" : "no") << "\n";

        if (noPasswordCheck->isChecked()) {
            out << "PasswordAuthentication no\n";
        } else {
            out << "PasswordAuthentication yes\n";
        }

        QStringList ips = allowedIPsEdit->toPlainText().split('\n', QString::SkipEmptyParts);
        for (const QString &ip : ips) {
            out << "ListenAddress " << ip.trimmed() << "\n";
        }

        QString username = usernameEdit->text().trimmed();
        if (!username.isEmpty()) {
            QStringList userWithIps;
            for (const QString &ip : ips) {
                userWithIps << username + "@" + ip.trimmed();
            }
            if (userWithIps.isEmpty())
                out << "AllowUsers " << username << "\n";
            else
                out << "AllowUsers " << userWithIps.join(' ') << "\n";
        }

        f.close();

        QMessageBox::information(this, "Saved", "Config saved to:\n" + filePath);
    }

    void startSshd() {
        if (sshdProcess->state() != QProcess::NotRunning) {
            QMessageBox::warning(this, "Warning", "sshd is already running");
            return;
        }
        saveConfig(); // Save before starting

        QString filePath = configPathEdit->text();

        // Example: sshd -f <config file> -D (no daemon)
        QString program = "sshd";
        QStringList args = {"-f", filePath, "-D"};

        outputEdit->appendPlainText("Starting sshd with: " + program + " " + args.join(' '));

        sshdProcess->start(program, args);
        if (!sshdProcess->waitForStarted(3000)) {
            outputEdit->appendPlainText("Failed to start sshd");
            return;
        }
        startBtn->setEnabled(false);
        stopBtn->setEnabled(true);
    }

    void stopSshd() {
        if (sshdProcess->state() == QProcess::NotRunning)
            return;
        sshdProcess->terminate();
        if (!sshdProcess->waitForFinished(3000)) {
            sshdProcess->kill();
            sshdProcess->waitForFinished();
        }
        outputEdit->appendPlainText("sshd stopped.");
        startBtn->setEnabled(true);
        stopBtn->setEnabled(false);
    }

    void readSshdOutput() {
        QByteArray output = sshdProcess->readAllStandardOutput();
        outputEdit->appendPlainText(QString::fromUtf8(output));
    }

    void readSshdError() {
        QByteArray output = sshdProcess->readAllStandardError();
        outputEdit->appendPlainText(QString::fromUtf8(output));
    }

    void sshdFinished(int exitCode, QProcess::ExitStatus exitStatus) {
        Q_UNUSED(exitCode);
        Q_UNUSED(exitStatus);
        outputEdit->appendPlainText("sshd process finished.");
        startBtn->setEnabled(true);
        stopBtn->setEnabled(false);
    }

private:
    QLineEdit *configPathEdit;
    QLineEdit *portEdit;
    QCheckBox *permitRootLoginCheck;
    QCheckBox *kbdInteractiveCheck;
    QPlainTextEdit *allowedIPsEdit;
    QLineEdit *loginGraceEdit;
    QLineEdit *maxAuthTriesEdit;
    QLineEdit *maxSessionsEdit;
    QLineEdit *usernameEdit;
    QLineEdit *passwordEdit;
    QCheckBox *noPasswordCheck;

    QPushButton *loadBtn;
    QPushButton *saveBtn;
    QPushButton *startBtn;
    QPushButton *stopBtn;

    QPlainTextEdit *outputEdit;
    QProcess *sshdProcess;
    QLineEdit *authorizedKeysEdit;
    QCheckBox *pubkeyAuthCheck;
    QPushButton *genKeyBtn;
    QPushButton *viewKeyBtn;
    QPushButton *authKeyBtn;

};



int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
    SshdConfigEditor w;
    w.resize(600, 700);
    w.show();
    return a.exec();
}
#include "main.moc"
