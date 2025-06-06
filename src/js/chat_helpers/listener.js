export const loadListeners = () => {
    document.getElementById("exit-chat-parameter").addEventListener('click', () => {
        document.getElementById("chat-parameter-page").style.display = "none";
    });
}