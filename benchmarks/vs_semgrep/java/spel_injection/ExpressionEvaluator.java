package com.example.spel;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class ExpressionEvaluator {

    private final ExpressionParser parser = new SpelExpressionParser();

    public Object evaluate(String expression) {
        StandardEvaluationContext ctx = new StandardEvaluationContext();
        ctx.setVariable("users", getSampleUsers());
        return parser.parseExpression(expression).getValue(ctx);
    }

    private List<Map<String, String>> getSampleUsers() {
        return List.of(
            Map.of("name", "alice", "role", "admin"),
            Map.of("name", "bob", "role", "user")
        );
    }
}
