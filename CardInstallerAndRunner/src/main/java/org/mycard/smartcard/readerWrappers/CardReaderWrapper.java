package org.mycard.smartcard.readerWrappers;

import org.mycard.smartcard.CardState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.mycard.smartcard.cardReader.readerImpl.RealCardReader;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;

public class CardReaderWrapper {

    final protected static Logger log = LoggerFactory.getLogger(CardReaderWrapper.class);

    protected RealCardReader reader;

    public RealCardReader getReader() {
        return reader;
    }

    public CardReaderWrapper(CardChannel cardChannel) throws CardException {
        reader = new RealCardReader(cardChannel, "Client Reader");
    }

    public CardState getAppletState(String AID){
        CardState cardState = CardState.NOT_INSERTED;

        if (reader.getApduRunner().getChannel() != null ) {

            try {
                reader.selectAID(AID);

                // Determine state of client applet on client card
                cardState = CardState.INSTALLED;



            } catch (CardException e) {
                cardState = CardState.EMPTY;
            }

        }

        return cardState;
    }

}
