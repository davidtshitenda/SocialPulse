import jwtDecode from 'jwt-decode';

document.getElementById('loginForm').addEventListener('submit', function(event) {

    let username = document.getElementById('username').value;
    let password = document.getElementById('password').value;

    if (!username) {
        alert("Username field cannot be blank");
        event.preventDefault();
        return;
    }

    if (!password) {
        alert("Password field cannot be blank");
        event.preventDefault();
        return;
    }

});
