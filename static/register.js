document.getElementById('contactForm').addEventListener('submit', function(event) {
    event.preventDefault();

    let password = document.getElementById('password').value;
    let confirm_password = document.getElementById('confirm_password').vale;
    let email = document.getElementById('email_address').value;
    let username = document.getElementById('username').value;
    let email_format_regex = email_validation();
    let email_domain_regex = domain_validation();

    if (!username) {
        alert("Username field cannot be blank");
        event.preventDefault();
        return;
    }

    if (!validatePassword(password)) {
        alert("Password must have at least 1 special character and be at least 8 characters long");
        return;
    }

    if (!email_format_regex.test(email) || !email_domain_regex.test(email)) {
        alert("Invalid email address");
        return;
    }

    if (password != confirm_password) {
        alert("Passwords needs to match");
        return;
    }

    function email_validation() {
        let regex = /^[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}$/;
        return regex;
    }

    function domain_validation() {
        let regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        return regex;
    }

    function validatePassword(password) {
        let specialCharacters = ['!', '"', '#', '$', '%', '&', '\\', "'", '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~'];

        if (password.length < 8) {
            return false;
        }

        for (let i = 0; i < password.length; i++) {
            if (specialCharacters.includes(password[i])) {
                return true;
            }
        }

        return false;
    }
});
