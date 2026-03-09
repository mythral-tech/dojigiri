package com.example.spel;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserFilterService filterService;

    @GetMapping("/search")
    public Object search(@RequestParam String filter) {
        return filterService.applyFilter(filter);
    }
}
