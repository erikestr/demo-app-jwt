package com.example.demo.student;

import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    private static final List<Student> STUDENTS = Arrays.asList(                /*Adding Students using Simple ArrayList*/
            new Student(1, "James"),
            new Student(2, "Erik"),
            new Student(3, "Mariam")
    );

    @GetMapping
    public Student getStudent(                                                  /*Original -> @GetMapping(path = "{studentId}")*/
            @RequestParam(name = "id") Integer studentId,                       /*Original -> @PathVariable("{studentId}") Integer studentId*/
            @RequestParam(name = "name", required = false) String name){        /*This is a @RequestParam nor required on @GetMapping*/
        if (!name.isBlank()){                                 /*This is a test about params on GetMapping*/
            System.out.println("name = " + name);
        }
    return STUDENTS.stream()                                                    /*return a filtered Student on List<Student> STUDENTS*/
                .filter(student -> studentId.equals(student.getStudentId()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Student " + studentId + " doesnt exists"));
    }
}
