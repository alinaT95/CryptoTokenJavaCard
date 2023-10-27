package org.mycard;

import javax.smartcardio.CardException;

@FunctionalInterface
public interface CardTestTask {
    void startTask() throws CardException;
}

