package tn.solarchain.service.dto;

import tn.solarchain.domain.User;
import java.io.Serializable;
import java.util.Objects;

public class UserDTO implements Serializable {

    private static final long serialVersionUID = 1L;

    private String id;

    private String login;

    public UserDTO() {
    }

    public UserDTO(User user) {
        this.id = user.getId();
        this.login = user.getLogin();
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        UserDTO userDTO = (UserDTO) o;
        if (userDTO.getId() == null || getId() == null) {
            return false;
        }

        return Objects.equals(getId(), userDTO.getId()) && Objects.equals(getLogin(), userDTO.getLogin());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getId(), getLogin());
    }

    // prettier-ignore
    @Override
    public String toString() {
        return "UserDTO{" +
                "id='" + id + '\'' +
                ", login='" + login + '\'' +
                "}";
    }
}
