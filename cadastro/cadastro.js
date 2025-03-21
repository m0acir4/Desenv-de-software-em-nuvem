document.getElementById('cadastroForm').addEventListener('submit', async (event) => {
    event.preventDefault();

    const email = document.getElementById('email').value;
    const senha = document.getElementById('senha').value;

    try {
        const response = await fetch('http://localhost:3000/usuarios', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, senha }),
        });

        const result = await response.json();
    if (response.ok) {
        alert(result.message);
        document.getElementById('email').value = '';
        document.getElementById('senha').value = '';
    } else {
        // Exibe o erro mais específico
        alert(`Erro: ${result.message || 'Não foi possível cadastrar o usuário.'}`);
    }
} catch (error) {
    alert('Erro ao cadastrar usuário');
    console.error(error);
}
});
