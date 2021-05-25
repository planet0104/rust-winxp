#include <iostream>
#include <locale.h>
#include <string>  
#include "httptool.hpp"

using namespace std;
int main() {
    //设备密钥
    string devicekey = "xuANDmBlTzPIuLTD";
    //随机密钥
    char* aeskey = aes_random_key128();
    // char* aeskey = (char*)"+Xww8uzS7et+qrcz0W/inQ==";
    printval("AES密钥:", aeskey);

    //获取公钥
    printval("获取公钥...", "");
    http_result_t* pubkeyResult = http_get("https://socket.fangte.site/getPubkey");
    // http_result_t* pubkeyResult = http_get("http://localhost:8080/getPubkey");

    char* errormsg = NULL;
    if(!http_result_success(pubkeyResult)){
        errormsg = http_result_error_info(pubkeyResult, "gbk");
        printval("", errormsg);   
        return -1;
    }
    char* pubkey = http_result_content(pubkeyResult, "gbk");
    //加密关键数据
    char* encryptedKey = rsa_public_encrypt(pubkey, devicekey.c_str());
    char* encryptedAesKey = rsa_public_encrypt(pubkey, aeskey);

    if(NULL==pubkey){
        return -1;
    }

    const char *getBarcodeMsg[8] = {"key", encryptedKey,
                                    "aesKey", encryptedAesKey,
                                    "bizNo", "201901141000",
                                    "amount", "0.15"};
    //获取付款码
    printval("获取付款码...", "");
    http_result_t* getBarcodeResult = http_post_json("https://socket.fangte.site/getBarCode", getBarcodeMsg, 8);
    // http_result_t* getBarcodeResult = http_post_json("http://localhost:8080/getBarCode", getBarcodeMsg, 8);

    char* resultStr = http_result_content(getBarcodeResult, "gbk");

    printval("", resultStr);
    char* result = aes_decrypt(resultStr, aeskey);

    printval("AES解密: ", result);

    http_result_free(pubkeyResult);
    free_string(errormsg);
    free_string(aeskey);
    free_string(encryptedKey);
    free_string(encryptedAesKey);
    free_string(resultStr);
    free_string(result);
    http_result_free(getBarcodeResult);
    return 0;
}