import "bootstrap/js/dist/alert";

export enum AlertType {
    Error = "danger",
    Success = "success",
}

export function showAlert(type: AlertType, message: string) {
    const html = `\
    <div class="alert alert-${type} alert-dismissible fade show" role="alert">
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    </div>`;
    document.getElementById("alerts")?.insertAdjacentHTML("beforeend", html);
}

type HandlerFn = (username: string, password: string) => Promise<void>;
export function handleForm(fn: HandlerFn) {
    document
        .querySelector("form")!
        .addEventListener("submit", async function (event: Event) {
            // prevent form submission
            event.preventDefault();
            // disable submit button
            (document.getElementById("submit") as HTMLButtonElement).disabled =
                true;
            try {
                const form = new FormData(event.target as HTMLFormElement);
                const username = form.get("username")!.toString().trim();
                const password = form.get("password")!.toString().trim();
                const confirm = form.get("confirm-password");
                if (confirm && password != confirm.toString().trim()) {
                    throw new Error("Passwords must match");
                }
                await fn(username, password);
            } catch (error: any) {
                showAlert(AlertType.Error, error.message);
            }
            // enable submit button
            (document.getElementById("submit") as HTMLButtonElement).disabled =
                false;
            // prevent form submission
            return false;
        });
}
