package org.mycard.smartcard.pcscWrapper.helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.mycard.common.ByteArrayHelper.hex;

public class SessionKeys {

    final private static Logger log = LoggerFactory.getLogger(SessionKeys.class);

    public final byte[] encKey;
    public final byte[] macKey;
    public final byte[] decKey;


    public SessionKeys(byte[] encKey, byte[] macKey, byte[] decKey) {
        this.encKey = encKey;
        this.macKey = macKey;
        this.decKey = decKey;
    }

    public void toLog(){
        log.debug("Session DEC: " + hex(this.decKey));
        log.debug("Session ENC: " + hex(this.encKey));
        log.debug("Session MAC: " + hex(this.macKey));
        log.debug("-----------------------------------------");
    }

}
