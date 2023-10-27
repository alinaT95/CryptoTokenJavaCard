package org.mycard.smartcard;

public class CardReaderWrapperState {

    private String state = "1";

    public CardReaderWrapperState(boolean clientCardReaderWrapperState){
        setState(clientCardReaderWrapperState);
    }

    public void setState(boolean clientCardReaderWrapperState) {
        state = clientCardReaderWrapperState ? "2" : "1";
    }

    public void setState(String state){
        if ((state.equals("1")) || (state.equals("2"))) {
            this.state = state;
        }
    }

    public String getState(){
        return state;
    }

    public boolean equals(CardReaderWrapperState cardReaderHelpersState) {
        return this.state == cardReaderHelpersState.state;
    }

}
