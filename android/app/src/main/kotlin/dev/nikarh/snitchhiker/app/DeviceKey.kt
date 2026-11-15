package dev.nikarh.snitchhiker.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * This device's key: what nodes know it by. Its 32 bytes are kept encrypted (AES-GCM) under a key the Android
 * Keystore holds and never lets out, in the app's private files, excluded from every backup.
 */
object DeviceKey {
    private const val ALIAS = "snitchhiker-device-key"
    private const val FILE = "device.key"
    private const val IV_BYTES = 12
    private const val TAG_BITS = 128

    private fun wrappingKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(ALIAS, null) as SecretKey?)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec
                .Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    /** The key, made the first time. */
    @Synchronized
    fun get(context: Context): ByteArray {
        val file = File(context.noBackupFilesDir, FILE)
        if (file.exists()) {
            val stored = file.readBytes()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, wrappingKey(), GCMParameterSpec(TAG_BITS, stored, 0, IV_BYTES))
            return cipher.doFinal(stored, IV_BYTES, stored.size - IV_BYTES)
        }
        val key = Native.generateKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey())
        file.writeBytes(cipher.iv + cipher.doFinal(key))
        return key
    }
}
