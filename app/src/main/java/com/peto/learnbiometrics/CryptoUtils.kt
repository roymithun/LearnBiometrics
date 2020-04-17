package com.peto.learnbiometrics

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey


class CryptoUtils {
    companion object {
        fun generateSecretKey(keyGenParameterSpec: KeyGenParameterSpec) {
            val keyGenerator =
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            keyGenerator.init(keyGenParameterSpec)
            keyGenerator.generateKey()
        }

        fun getSecretKey(): SecretKey {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            // Before the keystore can be accessed, it must be loaded.
            keyStore.load(null)
            return keyStore.getKey("PetoKey", null) as SecretKey
        }

        fun getCipher(): Cipher {
            return Cipher.getInstance(
                KeyProperties.KEY_ALGORITHM_AES + "/"
                        + KeyProperties.BLOCK_MODE_CBC + "/"
                        + KeyProperties.ENCRYPTION_PADDING_PKCS7
            )
        }

        /*fun initCipher(context: Context, mode: Int) {
            val iv: ByteArray
            val cipher: Cipher = getCipher()
            val ivParams: IvParameterSpec
            if (mode == Cipher.ENCRYPT_MODE) {
                cipher.init(mode, generateKey())
                ivParams = cipher.parameters.getParameterSpec(IvParameterSpec::class.java)
                iv = ivParams.iv
                var fos = context.openFileOutput(IV_FILE, Context.MODE_PRIVATE)
                fos.write(iv)
                fos.close()
            } else {
                key = (keyStore.getKey(KEY_NAME, null) as SecretKey).toInt()
                val file = File(context.getFilesDir() + "/" + IV_FILE)
                val fileSize = file.length() as Int
                iv = ByteArray(fileSize)
                val fis = context.openFileInput(IV_FILE)
                fis.read(iv, 0, fileSize)
                fis.close()
                ivParams = IvParameterSpec(iv)
                cipher.init(mode, key, ivParams)
            }
            mCryptoObject = FingerprintManager.CryptoObject(cipher)
        }*/
    }
}