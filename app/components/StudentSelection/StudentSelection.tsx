interface StudentSelectionProps {
  formData: any;
  setFormData: (data: any) => void;
  onNext: () => void;
  onBack: () => void;
}

export default function StudentSelection({
  formData,
  setFormData,
  onNext,
  onBack
}: StudentSelectionProps) {
  // 실제로는 API나 데이터베이스에서 가져올 학생 목록
  const students = [
    { id: 1, name: "김철수", grade: "1", class: "1" },
    { id: 2, name: "이영희", grade: "1", class: "2" },
    // ... 더 많은 학생들
  ];

  const handleStudentSelection = (studentId: number) => {
    if (formData.students.includes(studentId)) {
      setFormData({ ...formData, students: formData.students.filter((id: number) => id !== studentId) });
    } else {
      setFormData({ ...formData, students: [...formData.students, studentId] });
    }
  };

  return (
    <div>
      <h2 className="text-xl font-semibold mb-4">참여 학생을 선택해주세요</h2>
      
      <div className="grid grid-cols-2 gap-4 mb-6">
        {students.map((student) => (
          <button
            key={student.id}
            onClick={() => handleStudentSelection(student.id)}
            className={`
              p-4 rounded-lg border text-left transition-all
              ${formData.students.includes(student.id)
                ? 'border-blue-500 bg-blue-50 text-blue-600' 
                : 'border-gray-200 hover:border-gray-300'
              }
            `}
          >
            <div>{student.name}</div>
            <div className="text-sm text-gray-500">{student.class}</div>
          </button>
        ))}
      </div>

      <div className="flex gap-3 mt-8">
        <button
          onClick={onBack}
          className="w-full py-3.5 px-4 rounded-xl border border-gray-200 text-[17px] text-gray-700 font-medium hover:bg-gray-50 transition-colors"
        >
          이전으로
        </button>
        <button
          onClick={onNext}
          disabled={formData.students.length === 0}
          className="w-full py-3.5 px-4 rounded-xl bg-blue-500 text-[17px] text-white font-medium hover:bg-blue-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          다음으로
        </button>
      </div>
    </div>
  );
}