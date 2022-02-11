package com.example.demo.security;

import com.google.common.collect.Sets;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

import static com.example.demo.security.ApplicationUserPermission.*;

public enum  ApplicationUserRole {                                                                   /*enums of roles*/
    STUDENT(Sets.newHashSet()),                                                                     /*sets of name roles*/
    ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE)),
    ADMINTRAINEE(Sets.newHashSet(COURSE_READ, STUDENT_READ));

    private final Set<ApplicationUserPermission> permission;                                        /*instance of Permissions*/

    ApplicationUserRole(Set<ApplicationUserPermission> permission) {                                /*Constructor*/
        this.permission = permission;
    }

    public Set<ApplicationUserPermission> getPermission() {                                         /*Getter*/
        return permission;
    }

    public Set<SimpleGrantedAuthority> getGrantedAuthorities(){                                       /*Getter Converse to GrantedAuthority*/
        Set<SimpleGrantedAuthority> permissions = getPermission().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
        permissions.add(new SimpleGrantedAuthority("ROLE_"+this.name()));
        return permissions;
    }
}
