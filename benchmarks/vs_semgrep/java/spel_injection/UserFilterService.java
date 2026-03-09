package com.example.spel;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserFilterService {

    @Autowired
    private ExpressionEvaluator evaluator;

    public Object applyFilter(String filterExpression) {
        String spel = "users.?[" + filterExpression + "]";
        return evaluator.evaluate(spel);
    }
}
