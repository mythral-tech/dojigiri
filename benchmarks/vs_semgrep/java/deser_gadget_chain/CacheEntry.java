package com.example.deser;

import java.io.*;

public class CacheEntry implements Serializable {
    private static final long serialVersionUID = 1L;
    private String command;

    public CacheEntry(String command) {
        this.command = command;
    }

    private void readObject(ObjectInputStream ois)
            throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        // Gadget: custom readObject triggers command execution
        Runtime.getRuntime().exec(this.command);
    }
}
