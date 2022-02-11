package com.example.demo.security;

public enum ApplicationUserPermission {                 /*enums of permissions*/
    STUDENT_READ("student:read"),                       /*sets of name permission*/
    STUDENT_WRITE("student:write"),
    COURSE_READ("course:read"),
    COURSE_WRITE("course:write");

    private final String permission;                    /*JPA assign*/

    ApplicationUserPermission(String permission) {      /*Constructor*/
        this.permission = permission;
    }

    public String getPermission() {                     /*Getter*/
        return permission;
    }
}
