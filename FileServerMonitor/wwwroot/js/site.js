// Please see documentation at https://learn.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Write your JavaScript code.
function getActionChip(action) {
    if (!action) return `<span class="action-chip bg-gray-200 text-gray-700">Unknown</span>`;

    const lower = action.toLowerCase();
    let cls = '';

    switch (lower) {
        case 'read (open)':
        case 'execute/open':
            cls = 'bg-green-100 text-green-800';   // Open
            break;
        case 'write (modify)':
        case 'append (modify)':
            cls = 'bg-yellow-100 text-yellow-800'; // Modify
            break;
        case 'delete':
        case 'delete child':
            cls = 'bg-red-100 text-red-800';       // Delete
            break;
        case 'rename':
            cls = 'bg-blue-100 text-blue-800';     // Rename
            break;
        case 'close handle':
            cls = 'bg-purple-100 text-purple-800'; // Close
            break;
        default:
            cls = 'bg-gray-200 text-gray-700';      // fallback / unknown
    }

    return `<span class="action-chip ${cls}">${action}</span>`;
}
