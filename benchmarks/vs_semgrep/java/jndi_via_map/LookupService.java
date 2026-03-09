package com.example.jndi;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.http.*;
import java.io.*;
import java.util.*;

public class LookupService extends HttpServlet {

    private final Map<String, String> resourceRegistry = new HashMap<>();

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        String name = req.getParameter("resource_name");
        String jndiPath = req.getParameter("jndi_path");
        resourceRegistry.put(name, jndiPath);
        resp.getWriter().write("Registered: " + name);
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        String name = req.getParameter("resource_name");
        String path = resourceRegistry.get(name);

        if (path == null) {
            resp.sendError(404);
            return;
        }

        try {
            Context ctx = new InitialContext();
            Object resource = ctx.lookup(path);
            resp.getWriter().write("Found: " + resource);
        } catch (NamingException e) {
            resp.sendError(500, e.getMessage());
        }
    }
}
