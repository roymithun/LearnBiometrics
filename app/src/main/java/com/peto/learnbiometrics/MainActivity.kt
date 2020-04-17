package com.peto.learnbiometrics

import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import android.widget.Button
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.nio.charset.Charset
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec

class MainActivity : AppCompatActivity() {

    companion object {
        val TAG = MainActivity::class.java.simpleName
    }

    lateinit var ivByteArray: ByteArray
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val biometricPrompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    Toast.makeText(
                        applicationContext,
                        "Authentication error: $errString", Toast.LENGTH_SHORT
                    )
                        .show()
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    /*Toast.makeText(
                        applicationContext,
                        "Authentication succeeded!", Toast.LENGTH_SHORT
                    )
//                        .show()*/
//                    val encryptedInfo: ByteArray = result.cryptoObject.cipher?.doFinal(
//                        "plaintext-string".toByteArray(Charset.defaultCharset())
//                    )

                    val encryptedInfo = result.cryptoObject?.cipher?.doFinal(
                        "my plain text".toByteArray(
                            Charset.defaultCharset()
                        )
                    )
                    Log.d(TAG, "Encrypted information: " + Arrays.toString(encryptedInfo))

                    // DECRYPT
                    val cipher = CryptoUtils.getCipher()
                    val secretKey = CryptoUtils.getSecretKey()
                    cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(ivByteArray))
                    val decryptedByteArray = cipher.doFinal(encryptedInfo)
                    Log.d(
                        TAG,
                        "Decrypted information: " + String(decryptedByteArray)
                    )
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Toast.makeText(
                        applicationContext, "Authentication failed",
                        Toast.LENGTH_SHORT
                    )
                        .show()
                }
            })

        CryptoUtils.generateSecretKey(
            KeyGenParameterSpec.Builder(
                "PetoKey",
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                // set to false if want to decrypt
                .setUserAuthenticationRequired(true)
                // Invalidate the keys if the user has registered a new biometric
                // credential, such as a new fingerprint. Can call this method only
                // on Android 7.0 (API level 24) or higher. The variable
                // "invalidatedByBiometricEnrollment" is true by default.
                .setInvalidatedByBiometricEnrollment(true)
                .build()
        )

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric login for my app")
            .setSubtitle("Log in using your biometric credential")
            .setNegativeButtonText("Use account password")
            .build()
        findViewById<Button>(R.id.biometric_login).setOnClickListener {
            /*biometricPrompt.authenticate(
                promptInfo
            )*/
            // Exceptions are unhandled within this snippet.
            val cipher = CryptoUtils.getCipher()
            val secretKey = CryptoUtils.getSecretKey()
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            val ivParams = cipher.parameters.getParameterSpec(IvParameterSpec::class.java)
            ivByteArray = ivParams.iv
            biometricPrompt.authenticate(
                promptInfo,
                BiometricPrompt.CryptoObject(cipher)
            )
        }
    }

    private fun checkBiometricSupport() {
        val biometricManager = BiometricManager.from(this)

        when (biometricManager.canAuthenticate()) {
            BiometricManager.BIOMETRIC_SUCCESS ->
                Log.d(TAG, "App can authenticate using biometrics.")
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE ->
                Log.e(TAG, "No biometric features available on this device.")
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ->
                Log.e(TAG, "Biometric features are currently unavailable.")
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ->
                Log.e(
                    TAG, "The user hasn't associated " +
                            "any biometric credentials with their account."
                )
        }
    }
}
