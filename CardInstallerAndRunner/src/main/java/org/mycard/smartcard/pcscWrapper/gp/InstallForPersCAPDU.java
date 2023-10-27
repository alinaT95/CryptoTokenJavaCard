package org.mycard.smartcard.pcscWrapper.gp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.mycard.common.ByteArrayHelper.bConcat;

public class InstallForPersCAPDU extends InstallCAPDU {
    final private static Logger log = LoggerFactory.getLogger(InstallForPersCAPDU.class);


    public InstallForPersCAPDU(byte[] aid) throws Exception {
        super(InstallCAPDU.P1.PERS, bConcat(
                new byte[]{0},
                new byte[]{0},
                new byte[]{(byte) aid.length},
                aid,
                new byte[]{0},
                new byte[]{0},
                new byte[]{0}
        ));
    }



    @Override
    public String getDescr() {
        return "Install [for pers]";
    }

}


