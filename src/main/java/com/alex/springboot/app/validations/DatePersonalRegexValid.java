package com.alex.springboot.app.validations;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class DatePersonalRegexValid implements ConstraintValidator<DatePersonalRegex, String> {


    @Override
    public void initialize(DatePersonalRegex constraintAnnotation) {
        ConstraintValidator.super.initialize(constraintAnnotation);
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext constraintValidatorContext) {
        if (value.matches("[0-9]{2}[.][\\d]{3}[.][\\d]{3}[-][A-Z]{1}")) {
            return true; //retorna true si todo esta bien
        }
        return false; //retorna false cuando hay error y se muestra en la vista el error
    }
}
