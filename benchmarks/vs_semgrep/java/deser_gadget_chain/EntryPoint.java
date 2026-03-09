package com.example.deser;

import javax.servlet.http.*;
import java.io.*;

public class EntryPoint extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        try (ObjectInputStream ois =
                     new ObjectInputStream(req.getInputStream())) {
            Object obj = ois.readObject();
            resp.getWriter().write("Received: " + obj.getClass().getName());
        } catch (ClassNotFoundException e) {
            resp.sendError(400, "Bad payload");
        }
    }
}
