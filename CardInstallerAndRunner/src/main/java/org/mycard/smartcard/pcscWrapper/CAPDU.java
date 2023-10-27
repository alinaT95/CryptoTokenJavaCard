package org.mycard.smartcard.pcscWrapper;

import java.util.Arrays;
import java.util.List;

import static org.mycard.common.ByteArrayHelper.*;


public class CAPDU implements Cloneable {

    private final static int HEADER_LENGTH = 5;

    private byte[] bytes;

    public CAPDU(byte cla, byte ins, byte p1, byte p2, byte[] dataField, byte le) {
        if(dataField.length > 0) {
            this.bytes = bConcat(new byte[]{cla, ins, p1, p2, (byte) dataField.length}, dataField, new byte[]{le});
        }
        else {
            this.bytes = bConcat(new byte[]{cla, ins, p1, p2, le});
        }
    }

    public CAPDU(byte[] bytes) {
        this.bytes = bytes;
    }


    public CAPDU(int cla, int ins, int p1, int p2, byte[] dataField) {
        this((byte)cla, (byte)ins, (byte)p1, (byte)p2, dataField, (byte) 0);
    }

    public CAPDU(int cla, int ins, int p1, int p2) {
        this((byte)cla, (byte)ins, (byte)p1, (byte)p2, new byte[]{});
    }

    public CAPDU(int cla, int ins, int p1, int p2, int le) {
        this((byte)cla, (byte)ins, (byte)p1, (byte)p2, new byte[]{}, (byte) le);
    }

    public byte getCla() {
        return bytes[0];
    }

    public byte getIns() {
        return bytes[1];
    }

    public byte getP1() {
        return bytes[2];
    }

    public byte getP2() {
        return bytes[3];
    }

    public int getLc() {
        if(bytes.length <= 5) return 0;
        return (0xFF & bytes[4]);
    }

    public int getLe() {
        return bytes[bytes.length-1];
    }

    public byte[] getData() {
        if(getLc()> 0)
            return bSub(bytes, HEADER_LENGTH, bytes.length - HEADER_LENGTH - 1); // -1 because of Le
        else
            return new byte[0];
    }

    public byte[] getBytes() {
        return bytes;
    }

    public String getDescr(){return null;}

    public void printMore(RAPDU rapdu) {}

    public List<byte[]> getSuccessResults(){
        return Arrays.asList(new byte[]{(byte) 0x90,0x00}); //TODO: fix this place
    }

    private CAPDU saveClone()
    {
        try {
            return (CAPDU) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException(e);
        }
    }

    public CAPDU copy(byte[] bytes) {
        CAPDU clone = saveClone();
        clone.bytes = bCopy(bytes);
        return clone;
    }

    public CAPDU copy(byte cla, byte ins, byte p1, byte p2, byte[] dataField)  {
        CAPDU clone = saveClone();
        clone.bytes = bConcat(new byte[]{cla, ins, p1, p2, (byte) dataField.length}, dataField, new byte[]{(byte) getLe()});
        return clone;
    }

    @Override
    public String toString() {
        return "CAPDU '" + hex(getBytes()) + "'" + (getDescr()!=null ? " (" + getDescr() + ")" : "");
    }
}
