package org.mycard.smartcard.pcscWrapper.gp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.mycard.smartcard.pcscWrapper.CAPDU;
import org.mycard.smartcard.pcscWrapper.RAPDU;

import static org.mycard.common.ByteArrayHelper.*;

public class InitializeUpdateCAPDU extends CAPDU {
    final private static Logger log = LoggerFactory.getLogger(InitializeUpdateCAPDU.class);


    public InitializeUpdateCAPDU(byte[] hostChallenge) throws Exception {
        super(0x80, 0x50, 0x00, 0x00, hostChallenge);
    }


    @Override
    public String getDescr() {
        return "Initialize update";
    }

    @Override
    public void printMore(RAPDU rapdu) {
        byte[] data = rapdu.getData();
        log.debug("Key diversification data (10 bytes, used for derive card static keys): " + hex(bLeft(data, 10)));
        data = bRight(data, data.length - 10);
        log.debug("Key information (2 bytes, key version and secure protocol): " + hex(bLeft(data, 2)));
        data = bRight(data, data.length - 2);
        log.debug("Sequence Counter (2 bytes, used for create session keys): " + hex(bLeft(data, 2)));
        data = bRight(data, data.length - 2);
        log.debug("Card challenge (6 bytes): " + hex(bLeft(data, 6)));
        data = bRight(data, data.length - 6);
        log.debug("Card cryptogram (8 bytes): " + hex(data));

    }

}
