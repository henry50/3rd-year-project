import "bootstrap/js/dist/alert";

export enum AlertType {
    Error = "danger",
    Success = "success",
}

export function clearAlerts() {
    for (const child of document.getElementById("alerts")?.childNodes!) {
        child.remove();
    }
}

export function showAlert(type: AlertType, message: string) {
    const html = `\
    <div class="alert alert-${type} alert-dismissible fade show" role="alert">
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    </div>`;
    const errors = document
        .getElementById("alerts")
        ?.insertAdjacentHTML("beforeend", html);
}
