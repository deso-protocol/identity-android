package com.bitclout.identitydemo

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import com.bitclout.identity.LoginActivity

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        startActivity(LoginActivity.startIntent(this))
    }
}