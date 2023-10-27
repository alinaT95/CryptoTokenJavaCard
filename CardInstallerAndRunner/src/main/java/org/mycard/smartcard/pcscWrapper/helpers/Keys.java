package org.mycard.smartcard.pcscWrapper.helpers;

public class Keys {

    public final byte[] encKey;
    public final byte[] macKey;
    public final byte[] decKey;


    public Keys(byte[] encKey, byte[] macKey, byte[] decKey) {
        this.encKey = encKey;
        this.macKey = macKey;
        this.decKey = decKey;
    }
}
