package com.example.deser;

import java.io.*;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

public class TransformProxy implements InvocationHandler, Serializable {
    private static final long serialVersionUID = 1L;
    private final Object target;

    public TransformProxy(Object target) {
        this.target = target;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args)
            throws Throwable {
        // During deserialization, proxy resolution triggers target readObject
        return method.invoke(target, args);
    }
}
