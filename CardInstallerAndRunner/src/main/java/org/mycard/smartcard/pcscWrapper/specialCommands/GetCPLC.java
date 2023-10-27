package org.mycard.smartcard.pcscWrapper.specialCommands;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.mycard.smartcard.pcscWrapper.CAPDU;
import org.mycard.smartcard.pcscWrapper.RAPDU;

import java.util.ArrayList;
import java.util.List;

import static org.mycard.common.ByteArrayHelper.*;


public class GetCPLC extends CAPDU {
    final private static Logger log = LoggerFactory.getLogger(GetCPLC.class);


    public GetCPLC() {
        super(0x00, 0xCA, 0x9F, 0x7F, 0x00);
    }


    @Override
    public String getDescr() {
        return "Get CPLC (Card Production Life Cycle)";
    }

    @Override
    public List<byte[]> getSuccessResults() {
        List<byte[]> result = new ArrayList<>(super.getSuccessResults());
        result.add(new byte[]{0x6A, (byte) 0x88}); //this is result when there are not installed apps
        return result;
    }

    private static final byte STATE_LOADED = 0x1;
    private static final byte STATE_SELECTABLE = 0x7;
    private static final byte STATE_INSTALLED = 0x3;
    private static final byte STATE_LOCKED = (byte) 0x83;

    @Override
    public void printMore(RAPDU rapdu) {

        byte[] data = rapdu.getData();

        System.out.println("IC Fabricator: " + hex(bLeft(data, 2)));
        data = bSub(data, 2);

        System.out.println("IC Type: " + hex(bLeft(data, 2)));
        data = bSub(data, 2);

        System.out.println("Operating System ID: " + hex(bLeft(data, 2)));
        data = bSub(data, 2);

        System.out.println("Operating System release date: "  + hex(bLeft(data, 2)));
        data = bSub(data, 2);

        System.out.println("Operating System release level: "  + hex(bLeft(data, 2)));
        data = bSub(data, 2);

        System.out.println("IC Fabrication Date: " + hex(bLeft(data, 2))); //todo: format as a date
        data = bSub(data, 2);

        System.out.println("IC Serial Number: " + hex(bLeft(data, 4)));
        data = bSub(data, 4);

        System.out.println("IC Batch Identifier: " + hex(bLeft(data, 2)));
        data = bSub(data, 2);

        System.out.println("IC Module Fabricator: " + hex(bLeft(data, 2)));
        data = bSub(data, 2);

        System.out.println("IC Module Packaging Date: " + hex(bLeft(data, 2))); //todo: format as a date
        data = bSub(data, 2);

        System.out.println("ICC Manufacturer: " + hex(bLeft(data, 2)));
        data = bSub(data, 2);

        System.out.println("IC Embedding Date: " + hex(bLeft(data, 2)));
        data = bSub(data, 2);

        System.out.println("IC Pre-Personalizer: " + hex(bLeft(data, 2)));
        data = bSub(data, 2);

        System.out.println("IC Pre-Perso. Equipment Date: " + hex(bLeft(data, 2)));
        data = bSub(data, 2);

        System.out.println("IC Pre-Perso. Equipment ID: " + hex(bLeft(data, 4)));
        data = bSub(data, 4);

        System.out.println("IC Personalizer: " + hex(bLeft(data, 2)));
        data = bSub(data, 2);

        System.out.println("IC Personalization Date: " + hex(bLeft(data, 2)));
        data = bSub(data, 2);

        System.out.println("IC Perso. Equipment ID: " + hex(data));

    }

    public  static byte[] getIcSerialNumber(RAPDU rapdu) {
        return bSub(rapdu.getData(), 12, 4);
    }

    public  static  byte[] getIcBatchIdentifier(RAPDU rapdu) {
        return bSub(rapdu.getData(), 16, 2);
    }

    public  static byte[] getIcModuleFabricator(RAPDU rapdu) {
        return bSub(rapdu.getData(), 18, 2);
    }

}
