package com.deso.identitydemo

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import com.deso.identity.Identity
import com.deso.identity.models.EncryptedMessagesThread
import com.deso.identitydemo.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private val TEST_PUBLIC_KEY = "BC1YLhqTMSKvKk5NxsFCP4cNgj7utoGWptwMJ8EzBak8xo38fwNAWmX"
    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        val view = binding.root
        setContentView(view)
        binding.loginButton.setOnClickListener { Identity.login(this) }
        binding.logoutButton.setOnClickListener { Identity.logout(binding.logoutKey.text.toString()) }
        binding.encryptButton.setOnClickListener { testEncryptionAndDecryption() }
        binding.getKeysButton.setOnClickListener {
            binding.outputTextView.text = Identity.getLoggedInKeys().joinToString(",")
        }
    }


    private fun testEncryptionAndDecryption() {
        //TODO: use different public keys and have separate encryption and decryption
        val encryptedMessage =
            Identity.encrypt(binding.encryptMessage.text.toString(), TEST_PUBLIC_KEY, TEST_PUBLIC_KEY)
        val decryptedMessage = Identity.decrypt(
            EncryptedMessagesThread(TEST_PUBLIC_KEY, listOf(encryptedMessage)),
            TEST_PUBLIC_KEY
        )
        binding.outputTextView.text = decryptedMessage.joinToString(",")
    }
}
