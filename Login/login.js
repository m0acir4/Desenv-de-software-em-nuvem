document.getElementById('loginForm').addEventListener('submit', async (event) => {
    event.preventDefault();
// deixarei alguns comentários, pois o código não será feito só por mim. 
    const email = document.getElementById('email').value;
    const senha = document.getElementById('senha').value;

    try {
        const response = await fetch('http://localhost:3000/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, senha }),
        });

        const result = await response.json();
        if (response.ok) {
            // Armazenar o token no localStorage
            localStorage.setItem('token', result.token);
            localStorage.setItem('userId', result.userId);
            localStorage.setItem('email', result.email);

            alert('Login bem-sucedido!');
            // Redirecionar para a tela de gestão
            window.location.href = '/gestao/gestao.html'; 
        } else {
            alert(result.message || 'Erro ao fazer login');
        }
    } catch (error) {
        alert('Erro ao fazer login');
        console.error(error);
    }
});
