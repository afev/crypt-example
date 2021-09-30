package service;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
@NoArgsConstructor
public class ServiceResult<T> implements Serializable {
    private static final long serialVersionUID = 2654830017993891765L;

    private T result;
    private String error;

    public ServiceResult(T data) {
        result = data;
        error = null;
    }

    public ServiceResult(String error){
        result = null;
        this.error = error;
    }

    public boolean noError() {
        return error == null;
    }

    public boolean hasError(){
        return !noError();
    }
}
