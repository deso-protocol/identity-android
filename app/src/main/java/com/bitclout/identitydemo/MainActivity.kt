package com.bitclout.identitydemo

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import com.bitclout.identity.Identity
import com.bitclout.identitydemo.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        val view = binding.root
        setContentView(view)
        binding.loginButton.setOnClickListener { Identity.login(this) }
        binding.getKeysButton.setOnClickListener { binding.keysInfo.text = Identity.getLoggedInKeys().joinToString(",") }
    }
}