// URL do back-end
const apiUrl = 'http://localhost:3000/usuarios';
// Deixarei alguns comentários, pois o código não será feito só por mim. 
// Função para carregar os usuários na tabela
async function loadUsers() {
    const response = await fetch(apiUrl);
    const users = await response.json();
    const tableBody = document.querySelector('#usersTable tbody');
    tableBody.innerHTML = '';

    users.forEach(user => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${user.email}</td>
            <td>
                <button onclick="editUser('${user._id}')">Editar</button>
                <button onclick="deleteUser('${user._id}')">Excluir</button>
            </td>
        `;
        tableBody.appendChild(row);
    });
}

// Função para editar usuário
function editUser(userId) {
    const newEmail = prompt('Digite o novo e-mail:');
    const newPassword = prompt('Digite a nova senha:');
    
    fetch(`${apiUrl}/${userId}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email: newEmail, senha: newPassword })
    })
    .then(response => response.json())
    .then(() => {
        alert('Usuário editado com sucesso!');
        loadUsers(); // Recarrega os usuários
    })
    .catch(error => alert('Erro ao editar usuário: ' + error.message));
}

// Função para excluir usuário
function deleteUser(userId) {
    if (confirm('Tem certeza que deseja excluir este usuário?')) {
        fetch(`${apiUrl}/${userId}`, {
            method: 'DELETE',
        })
        .then(() => {
            alert('Usuário excluído com sucesso!');
            loadUsers(); // Recarrega os usuários
        })
        .catch(error => alert('Erro ao excluir usuário: ' + error.message));
    }
}

// Carrega os usuários na primeira vez
window.onload = loadUsers;
