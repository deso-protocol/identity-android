package com.bitclout.identity

import android.content.Context
import androidx.startup.Initializer

class IdentityInitializer : Initializer<Identity> {

    override fun create(context: Context): Identity {
        Identity.initialize(context)
        return Identity
    }

    override fun dependencies(): List<Class<out Initializer<*>>> = emptyList()
}