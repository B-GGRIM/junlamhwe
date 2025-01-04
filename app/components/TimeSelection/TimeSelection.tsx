interface TimeSelectionProps {
  formData: any;
  setFormData: (data: any) => void;
  onNext: () => void;
}

export default function TimeSelection({ formData, setFormData, onNext }: TimeSelectionProps) {
  return (
    <div className="max-w-2xl mx-auto bg-white p-8">
      <h2 className="text-2xl font-bold text-gray-900 mb-6">시간 선택</h2>
      <div className="space-y-4">
        <div className="grid grid-cols-1 gap-4">
          {[
            { value: "1차 면학", time: "19:00 - 21:00" },
            { value: "2차 면학", time: "21:00 - 23:40" },
          ].map((option) => (
            <label
              key={option.value}
              className={`
                relative p-4 rounded-xl cursor-pointer transition-all
                border-2 hover:border-blue-500
                ${formData.time === option.value 
                  ? 'border-blue-500 bg-blue-50' 
                  : 'border-gray-200 hover:bg-gray-50'}
              `}
            >
              <div className="flex items-center justify-between">
                <div className="flex flex-col">
                  <span className="text-lg font-medium text-gray-900">
                    {option.value}
                  </span>
                  <span className="text-sm text-gray-500">
                    {option.time}
                  </span>
                </div>
                <input
                  type="radio"
                  name="studyTime"
                  value={option.value}
                  checked={formData.time === option.value}
                  onChange={(e) => setFormData({ ...formData, time: e.target.value })}
                  className="w-5 h-5 text-blue-500 focus:ring-blue-500"
                />
              </div>
            </label>
          ))}
        </div>
        
        <button
          onClick={onNext}
          disabled={!formData.time}
          className={`
            w-full py-4 rounded-xl text-white font-medium text-lg transition-all
            ${formData.time 
              ? 'bg-blue-500 hover:bg-blue-600 shadow-sm' 
              : 'bg-gray-300 cursor-not-allowed'}
          `}
        >
          다음
        </button>
      </div>
    </div>
  );
}