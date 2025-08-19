document.addEventListener('DOMContentLoaded', () => {
    // Form validation
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', (e) => {
            const inputs = form.querySelectorAll('input[required], textarea[required]');
            let valid = true;
            inputs.forEach(input => {
                if (!input.value.trim()) {
                    valid = false;
                    input.classList.add('border-red-500');
                } else {
                    input.classList.remove('border-red-500');
                }
            });
            if (!valid) {
                e.preventDefault();
                alert('Please fill all required fields.');
            }
        });
    });

    // Chat polling
    const chatBox = document.getElementById('chatBox');
    if (chatBox) {
        const urlParams = new URLSearchParams(window.location.search);
        const userId = urlParams.get('user');
        if (userId) {
            setInterval(() => {
                fetch(`chat.php?user=${userId}&ajax=1`)
                    .then(response => response.text())
                    .then(data => {
                        chatBox.innerHTML = data;
                        chatBox.scrollTop = chatBox.scrollHeight;
                    });
            }, 5000);
        }
    }
});
function toggleComments(postId) {
    const commentSection = document.getElementById(`comments-${postId}`);
    commentSection.classList.toggle('hidden');
}

function togglePostType(type) {
    const mediaUpload = document.getElementById('media-upload');
    const pollOptions = document.getElementById('poll-options');
    mediaUpload.classList.add('hidden');
    pollOptions.classList.add('hidden');
    if (type === 'image' || type === 'video') {
        mediaUpload.classList.remove('hidden');
        document.getElementById('media').setAttribute('accept', type === 'video' ? 'video/mp4,video/mov' : 'image/jpeg,image/png,image/gif');
    } else if (type === 'poll') {
        pollOptions.classList.remove('hidden');
    }
}

function toggleComments(postId) {
    const commentSection = document.getElementById(`comments-${postId}`);
    commentSection.classList.toggle('hidden');
}
function togglePostType(type) {
    const mediaUpload = document.getElementById('media-upload');
    const pollOptions = document.getElementById('poll-options');
    mediaUpload.classList.add('hidden');
    pollOptions.classList.add('hidden');
    if (type === 'image' || type === 'video') {
        mediaUpload.classList.remove('hidden');
        document.getElementById('media').setAttribute('accept', type === 'video' ? 'video/mp4,video/mov' : 'image/jpeg,image/png,image/gif');
    } else if (type === 'poll') {
        pollOptions.classList.remove('hidden');
    }
}

function toggleComments(postId) {
    const commentSection = document.getElementById(`comments-${postId}`);
    commentSection.classList.toggle('hidden');
}