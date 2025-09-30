document.addEventListener('DOMContentLoaded', function() {
    const agreeCheckbox = document.getElementById('agree');
    const submitButton = document.getElementById('submit-button');

    if (agreeCheckbox && submitButton) {
        agreeCheckbox.addEventListener('change', function() {
            submitButton.disabled = !agreeCheckbox.checked;
        });
    }
});
