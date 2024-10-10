package org.example.authserver.interfaces;

import org.example.authserver.dto.AccountCreateRequest;
import org.example.authserver.entities.User;
import org.mapstruct.*;

@Mapper(componentModel = "spring")
public interface UserMapper {
    User toEntity(AccountCreateRequest accountCreateRequest);

    AccountCreateRequest toDto(User user);

    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    User partialUpdate(AccountCreateRequest accountCreateRequest, @MappingTarget User user);
}