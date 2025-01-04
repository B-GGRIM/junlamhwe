interface TeacherSelectionProps {
  formData: any;
  setFormData: (data: any) => void;
  onSubmit: () => void;
  onBack: () => void;
}

export default function TeacherSelection({
  formData,
  setFormData,
  onSubmit,
  onBack
}: TeacherSelectionProps) {
  // 실제로는 API나 데이터베이스에서 가져올 교사 목록
  const teachers = [
    { id: 1, name: "김선생", subject: "수학" },
    { id: 2, name: "박선생", subject: "과학" },
    // ... 더 많은 교사들
  ];

  return (
    <div>
      <h2 className="text-xl font-semibold mb-4">담당 교사를 선택해주세요</h2>
      
      <div className="grid grid-cols-2 gap-4 mb-6">
        {teachers.map((teacher) => (
          <button
            key={teacher.id}
            onClick={() => setFormData({ ...formData, teacher: teacher.id })}
            className={`
              p-4 rounded-lg border text-left transition-all
              ${formData.teacher === teacher.id
                ? 'border-blue-500 bg-blue-50 text-blue-600' 
                : 'border-gray-200 hover:border-gray-300'
              }
            `}
          >
            <div>{teacher.name}</div>
            <div className="text-sm text-gray-500">{teacher.subject}</div>
          </button>
        ))}
      </div>

      <div className="flex justify-between mt-6">
        <button
          onClick={onBack}
          className="px-6 py-2 border border-gray-300 rounded-lg hover:bg-gray-50"
        >
          이전
        </button>
        <button
          onClick={onSubmit}
          disabled={!formData.teacher}
          className="px-6 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 disabled:opacity-50"
        >
          제출하기
        </button>
      </div>
    </div>
  );
}