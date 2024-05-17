#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <string>

//�R���p�C���I�v�V����
//g++ -o RSA.exe RSA.cpp -I"C:\Program Files\OpenSSL-Win64\include" -L"C:\Program Files\OpenSSL-Win64\lib\VC\x64\MTd" -lssl -lcrypto -Wno-deprecated-declarations

// �L�[�y�A�̐���
RSA* createRSAKeyPair() {
    int keyLength = 2048;
    unsigned long e = RSA_F4; // ���J�w���i�ʏ��RSA_F4�j

    RSA* rsa = RSA_generate_key(keyLength, e, NULL, NULL);
    if (rsa == NULL) {
        std::cerr << "���̐����Ɏ��s���܂���" << std::endl;
        return NULL;
    }

    return rsa;
}

// ���J����PEM�`���Ŏ擾
std::string getPublicKey(RSA* rsa) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio, rsa);
    
    size_t pubKeyLen = BIO_pending(bio);
    char* pubKey = new char[pubKeyLen + 1];
    BIO_read(bio, pubKey, pubKeyLen);
    pubKey[pubKeyLen] = '\0';

    std::string publicKey(pubKey);
    delete[] pubKey;
    BIO_free_all(bio);

    return publicKey;
}

// �閧����PEM�`���Ŏ擾
std::string getPrivateKey(RSA* rsa) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);

    size_t privKeyLen = BIO_pending(bio);
    char* privKey = new char[privKeyLen + 1];
    BIO_read(bio, privKey, privKeyLen);
    privKey[privKeyLen] = '\0';

    std::string privateKey(privKey);
    delete[] privKey;
    BIO_free_all(bio);

    return privateKey;
}

// ���b�Z�[�W�̈Í���
std::string encryptMessage(RSA* rsa, const std::string& message) {
    size_t rsaLen = RSA_size(rsa);
    unsigned char* encryptedMessage = new unsigned char[rsaLen];

    int result = RSA_public_encrypt(message.length(), 
                                    reinterpret_cast<const unsigned char*>(message.c_str()), 
                                    encryptedMessage, 
                                    rsa, 
                                    RSA_PKCS1_PADDING);

    if (result == -1) {
        char* err = new char[130];
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        std::cerr << "�Í����Ɏ��s���܂��� " << err << std::endl;
        delete[] err;
        return "";
    }

    std::string encryptedString(reinterpret_cast<char*>(encryptedMessage), result);
    delete[] encryptedMessage;

    return encryptedString;
}

// ���b�Z�[�W�̕���
std::string decryptMessage(RSA* rsa, const std::string& encryptedMessage) {
    size_t rsaLen = RSA_size(rsa);
    unsigned char* decryptedMessage = new unsigned char[rsaLen];

    int result = RSA_private_decrypt(encryptedMessage.length(), 
                                     reinterpret_cast<const unsigned char*>(encryptedMessage.c_str()), 
                                     decryptedMessage, 
                                     rsa, 
                                     RSA_PKCS1_PADDING);

    if (result == -1) {
        char* err = new char[130];
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        std::cerr << "�����Ɏ��s���܂���" << err << std::endl;
        delete[] err;
        return "";
    }

    std::string decryptedString(reinterpret_cast<char*>(decryptedMessage), result);
    delete[] decryptedMessage;

    return decryptedString;
}

int main() {
    //�L�[�y�A�̐���
    RSA* rsa = createRSAKeyPair();
    if (rsa == NULL) {
        return -1;
    }

    
    std::string message ;
    // ������̓���
    std::cout << "��������͂��Ă�������: ";
    std::getline(std::cin,  message);

    //���J���Ɣ閧���̎擾�ƕ\��
    std::string publicKey = getPublicKey(rsa);
    std::string privateKey = getPrivateKey(rsa);
    std::cout << "\n���J��:\n" << publicKey << std::endl;
    std::cout << "�閧��:\n" << privateKey << std::endl;

    std::string encryptedMessage = encryptMessage(rsa, message);
    std::cout << "�Í������ꂽ������:\n-----BEGIN ENCRYPTED STRING-----\n" << encryptedMessage <<"\n-----END ENCRYPTED STRING-----\n"<< std::endl;

    //���b�Z�[�W�̕���
    std::string decryptedMessage = decryptMessage(rsa, encryptedMessage);
    std::cout << "�������ꂽ������: " << decryptedMessage << std::endl;

    //RSA�I�u�W�F�N�g�̉��
    RSA_free(rsa);

    return 0;
}