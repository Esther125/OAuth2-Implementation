TriggersDef = {
  createCard: {
    matchingFields: [
      'boardId',
      'listName',
      'userId',
      'swimlaneName',
      'cardTitle',
    ],
  },
  moveCard: {
    matchingFields: [
      'boardId',
      'listName',
      'oldListName',
      'userId',
      'swimlaneName',
      'cardTitle',
    ],
  },
  archivedCard: {
    matchingFields: ['boardId', 'userId', 'cardTitle'],
  },
  restoredCard: {
    matchingFields: ['boardId', 'userId', 'cardTitle'],
  },
  joinMember: {
    matchingFields: ['boardId', 'username', 'userId'],
  },
  unjoinMember: {
    matchingFields: ['boardId', 'username', 'userId'],
  },
  addChecklist: {
    matchingFields: ['boardId', 'checklistName', 'userId'],
  },
  removeChecklist: {
    matchingFields: ['boardId', 'checklistName', 'userId'],
  },
  completeChecklist: {
    matchingFields: ['boardId', 'checklistName', 'userId'],
  },
  uncompleteChecklist: {
    matchingFields: ['boardId', 'checklistName', 'userId'],
  },
  addedChecklistItem: {
    matchingFields: ['boardId', 'checklistItemName', 'userId'],
  },
  removedChecklistItem: {
    matchingFields: ['boardId', 'checklistItemName', 'userId'],
  },
  checkedItem: {
    matchingFields: ['boardId', 'checklistItemName', 'userId'],
  },
  uncheckedItem: {
    matchingFields: ['boardId', 'checklistItemName', 'userId'],
  },
  addAttachment: {
    matchingFields: ['boardId', 'userId'],
  },
  deleteAttachment: {
    matchingFields: ['boardId', 'userId'],
  },
  addedLabel: {
    matchingFields: ['boardId', 'labelId', 'userId'],
  },
  removedLabel: {
    matchingFields: ['boardId', 'labelId', 'userId'],
  },
};
